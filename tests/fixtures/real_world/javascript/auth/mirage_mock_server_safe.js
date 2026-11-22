import {Response} from 'miragejs';

// ember-cli-mirage mock server: the handlers run in the browser against an
// in-memory database, so there is no request boundary to authorize.
export default function mockServer(server) {
    server.get('/posts/:id/', function ({posts}, {params}) {
        let {id} = params;
        let post = posts.find(id);
        return post || new Response(404, {}, {});
    });
    server.put('/newsletters/:id/', function ({newsletters}, {params}) {
        const attrs = this.normalizedRequestAttrs();
        const newsletter = newsletters.find(params.id);
        return newsletter.update(attrs);
    });
}
