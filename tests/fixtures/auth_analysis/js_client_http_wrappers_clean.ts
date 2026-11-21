// Front-end data helpers call their own backend over HTTP.  `axios.delete`
// and `api.put` are requests, not database writes, and the browser is not
// where ownership is enforced.  Pinned in `auth_analysis_tests`.
import axios from 'axios';

export async function deleteTodo(todoId: string) {
  await axios.delete(`/api/todos/${todoId}`);
}

export const updateTodo = async (id: string, data: any) => {
  return api.put(`/todos/${id}`, data);
};

export async function loadTodo(todoId: string) {
  return http.get(`/api/todos/${todoId}`);
}
