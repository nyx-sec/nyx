const { nodeDefinitions } = require('graphql-relay');

function resolveNode(globalId) {
  return globalId;
}

function normalizeId(id) {
  return String(id);
}

module.exports = { resolveNode, normalizeId, nodeDefinitions };
