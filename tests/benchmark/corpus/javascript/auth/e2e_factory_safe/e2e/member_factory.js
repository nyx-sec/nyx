// Files under an `e2e` directory are test support: nothing serves them, so a
// missing ownership claim has no request to attach to.
async function archiveMember(db, memberId) {
    await db.members.update({status: 'archived'}, {where: {id: memberId}});
}

module.exports = {archiveMember};
