# Phase 04 follow-up regression fixture: the sink lives in a class method
# that has no callers in the whole-program callgraph. The reverse-edge BFS
# in `find_entry_via_callgraph` must miss (helper is inside a class, so
# `is_entry_point`'s zero-in-degree heuristic does not apply), and the
# strict `derive_from_callgraph_walk_only` pre-step must defer to the
# strategy ladder so the substring `.http.` rule-id fallback does NOT
# short-circuit the more precise `FromFlowSteps` strategy.


class Stuff:
    def helper(self, arg):
        import os
        os.system(arg)  # sink: command injection
