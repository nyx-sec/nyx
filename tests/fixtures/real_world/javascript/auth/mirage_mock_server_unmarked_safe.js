// A Mirage config without the `miragejs` import: the handler signature
// (schema + destructured request) still marks it as a browser mock.
export default function mockServer(server) {
    server.get('/members/:id/', function ({members}, {params}) {
        return members.find(params.id);
    });
    server.del('/members/:id/', function ({members}, {params}) {
        members.find(params.id).destroy();
    });
}
