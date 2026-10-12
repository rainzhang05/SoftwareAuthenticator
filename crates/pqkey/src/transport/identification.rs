//! Bounded daemon identification, separate from the CTAP worker and presence.

use super::*;
use ctaphid_host::IdentificationRequest;

/// Deliver a device identification notification by `deadline`.
///
/// Implementations must bound all delivery work by the original deadline,
/// including connecting and cleanup. They never ask for user presence.
pub trait Identifier: Send {
    fn identify(&mut self, deadline: Instant) -> io::Result<()>;
}

impl<F: FnMut(Instant) -> io::Result<()> + Send> Identifier for F {
    fn identify(&mut self, deadline: Instant) -> io::Result<()> {
        self(deadline)
    }
}

pub(super) struct IdentificationWorker {
    requests: Option<mpsc::SyncSender<(IdentificationRequest, Instant)>>,
    responses: mpsc::Receiver<(u64, bool)>,
}

impl IdentificationWorker {
    pub(super) fn spawn<'scope, 'env: 'scope>(
        scope: &'scope thread::Scope<'scope, 'env>,
        mut identifier: impl Identifier + 'scope,
        wake: UnixStream,
    ) -> io::Result<(Self, thread::ScopedJoinHandle<'scope, ()>)> {
        // One running attempt and at most one queued after resynchronization.
        let (requests, receiver) = mpsc::sync_channel::<(IdentificationRequest, Instant)>(1);
        let (sender, responses) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("key-identification".into())
            .spawn_scoped(scope, move || {
                for (request, deadline) in receiver {
                    let delivered =
                        Instant::now() < deadline && identifier.identify(deadline).is_ok();
                    if sender.send((request.token, delivered)).is_err() {
                        break;
                    }
                    let _ = (&wake).write(&[0]);
                }
            })?;
        Ok((
            Self {
                requests: Some(requests),
                responses,
            },
            worker,
        ))
    }

    pub(super) fn submit(&self, request: IdentificationRequest, epoch: Instant) -> bool {
        self.requests.as_ref().is_some_and(|sender| {
            sender
                .try_send((request, epoch + Duration::from_millis(request.deadline)))
                .is_ok()
        })
    }

    pub(super) fn response(&self) -> Option<(u64, bool)> {
        self.responses.try_recv().ok()
    }

    pub(super) fn stop(&mut self) {
        self.requests = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_attempt_runs_and_one_can_queue_without_blocking_the_reader() {
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let (wake, _reader) = UnixStream::pair().unwrap();
        wake.set_nonblocking(true).unwrap();
        thread::scope(|scope| {
            let (mut worker, handle) = IdentificationWorker::spawn(
                scope,
                move |deadline: Instant| {
                    entered.send(()).unwrap();
                    released
                        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                        .map_err(io::Error::other)?;
                    Ok(())
                },
                wake,
            )
            .unwrap();
            let epoch = Instant::now();
            let request = |token| IdentificationRequest {
                token,
                deadline: 500,
            };
            assert!(worker.submit(request(0), epoch));
            entering.recv_timeout(Duration::from_secs(1)).unwrap();
            assert!(worker.submit(request(1), epoch));
            assert!(!worker.submit(request(2), epoch));
            release.send(()).unwrap();
            release.send(()).unwrap();
            worker.stop();
            handle.join().unwrap();
            assert_eq!(worker.response(), Some((0, true)));
            assert_eq!(worker.response(), Some((1, true)));
            assert!(worker.response().is_none());
            assert!(!worker.submit(request(3), epoch));
        });
    }

    #[test]
    fn expired_queued_work_is_never_delivered_and_errors_are_results() {
        for deadline in [0, 500] {
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let attempts = calls.clone();
            let (wake, _reader) = UnixStream::pair().unwrap();
            thread::scope(|scope| {
                let (mut worker, handle) = IdentificationWorker::spawn(
                    scope,
                    move |_| {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        Err(io::Error::other("scripted notification error"))
                    },
                    wake,
                )
                .unwrap();
                assert!(
                    worker.submit(IdentificationRequest { token: 0, deadline }, Instant::now())
                );
                worker.stop();
                handle.join().unwrap();
                assert_eq!(worker.response(), Some((0, false)));
            });
            assert_eq!(calls.load(Ordering::SeqCst), usize::from(deadline != 0));
        }
    }
}
