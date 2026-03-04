<?php
class UserController {
    public function view() {
        $id = $_GET['id'] ?? '';
    }

    public function update() {
        $user_id = $_POST['user_id'] ?? '';
        if ($user_id !== Auth::id()) {
            return;
        }
    }

    public function delete() {
        $id = $_POST['id'] ?? '';
    }
}
