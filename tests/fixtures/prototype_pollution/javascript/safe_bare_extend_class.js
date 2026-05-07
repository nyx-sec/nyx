// Safe: Backbone-style class extension shares the `extend` suffix but
// passes an object literal as arg 0, never the literal `true` deep flag.
// The bare `extend` SinkGate uses `LiteralOnly` activation so this call
// does not produce a PROTOTYPE_POLLUTION finding.
const Backbone = require('backbone');

const UserModel = Backbone.Model.extend({
    defaults: { name: '', id: 0 },
    initialize: function () {
        this.set('createdAt', Date.now());
    },
});

module.exports = UserModel;
