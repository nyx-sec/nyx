// The same helper in a production path: the id is caller supplied and the
// update is unscoped.
async function archiveMember(db, memberId) {
    await db.members.update({status: 'archived'}, {where: {id: memberId}});
}

module.exports = {archiveMember};
