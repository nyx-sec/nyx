<?php
function delete_post_handler() {
    global $wpdb;
    $id = $_GET['id'];
    if (!is_numeric($id)) {
        wp_die('bad id');
    }
    $wpdb->query("DELETE FROM wp_posts WHERE ID = " . $id);
}
