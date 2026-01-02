# Task Completion Checklist

## Before Completing a Task
1. Run `cargo build` to verify compilation
2. Run `cargo clippy` for linting (if available)
3. Run `cargo fmt` to format code (if required)
4. Run `cargo test` if tests exist

## For Repository Tasks
- Ensure proper imports from crate modules
- Follow existing repository patterns
- Update mod.rs to export new repositories
- Use appropriate return types (AppResult<T>)

## Git Workflow
1. `git add <files>` - Stage changes
2. `git commit -m "feat: description"` - Commit with conventional message
3. Verify with `git status`
