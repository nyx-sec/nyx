// Safe: Backbone-style class extension in TS shares the `extend` suffix
// but passes an object literal as arg 0, never the literal `true` deep
// flag.  `LiteralOnly` activation suppresses the finding.
import * as Backbone from 'backbone';

export const UserModel = Backbone.Model.extend({
    defaults: { name: '', id: 0 },
    initialize: function () {
        (this as unknown as { set: (k: string, v: unknown) => void }).set(
            'createdAt',
            Date.now(),
        );
    },
});
