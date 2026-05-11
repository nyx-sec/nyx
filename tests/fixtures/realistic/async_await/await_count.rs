// Phase 12 ssa-equivalence fixture (Rust): three `await_expression` nodes
// in distinct positions (let-binding, statement-expression, implicit
// return) used by `await_emits_at_most_one_assign_per_node` to assert
// the SSA lowering does not double-fire Assign ops on a single
// AwaitForward CFG node.
async fn pass(s: String) -> String {
    s
}

pub async fn run() -> String {
    let env = std::env::var("X").unwrap_or_default();
    let fut1 = pass(env);
    let r1 = fut1.await;
    let fut2 = pass(r1);
    fut2.await
}
