use std::process::ExitCode;

#[global_allocator]
static ALLOCATOR: pqkey::allocator::WipingAllocator<std::alloc::System> =
    pqkey::allocator::WipingAllocator::new(std::alloc::System);

fn main() -> ExitCode {
    pqkey::cli::main()
}
