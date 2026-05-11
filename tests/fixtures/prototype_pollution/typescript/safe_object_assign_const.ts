// Safe: Object.assign with a constant-source object literal.  No taint
// reaches the merge so PROTOTYPE_POLLUTION does not fire.
export function build(): Record<string, number> {
    const target: Record<string, number> = {};
    Object.assign(target, { x: 1, y: 2 });
    return target;
}
