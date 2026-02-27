<?php

class UserController {
    public function show() {
        $id = $_GET['id'];
        $sql = "SELECT * FROM users WHERE id=" . $id;
        DB::select($sql);
    }
}
