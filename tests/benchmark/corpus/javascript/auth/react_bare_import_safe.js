import {useEffect} from 'react';
import setupGhostApi from '../utils/api';

// A file that imports the React runtime is browser code: the SDK call goes to
// the backend, where the authorization check belongs.
export const FeedbackPage = ({uuid, postId, key, score, siteUrl}) => {
    useEffect(() => { sendFeedback({siteUrl, uuid, key, postId, score}); });
    return null;
};

async function sendFeedback({siteUrl, uuid, key, postId, score}, api) {
    const ghostApi = api || setupGhostApi({siteUrl});
    await ghostApi.feedback.add({uuid, postId, key, score});
}
