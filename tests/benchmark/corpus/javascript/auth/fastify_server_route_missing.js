const fastify = require('fastify');
const server = fastify();

// A real Fastify app: the file imports fastify, so `server.get` is a route and
// the lookup by a client chosen id needs an ownership check.
server.get('/posts/:id', async (request, reply) => {
    const post = await Post.findByPk(request.params.id);
    reply.send(post);
});

server.listen({port: 3000});
