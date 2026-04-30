// Constructor cap narrowing: a third-party SDK client constructed from an
// env-derived secret returns objects whose string properties are
// SDK-generated, not derived from the secret in any path-shaped sense.
// `Cap::all()` flowing through `new Stripe(key)` must drop FILE_IO so
// downstream `fs.writeFileSync` of an SDK property does not flag a phantom
// path-traversal flow.
var fs = require('fs');

var key = process.env.STRIPE_SECRET_KEY;
var stripe = new Stripe(key);

async function setup() {
    var price = await stripe.prices.create({ unit_amount: 9599 });
    var line = 'PRICE_ID="' + price.id + '"';
    fs.writeFileSync('./out.env', line);
}
setup();
