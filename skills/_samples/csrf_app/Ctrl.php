<?php
class Ctrl {
    public function postA() {
        $x = $_POST['x'] ?? '';
    }
    public function postB() {
        $y = $_POST['y'] ?? '';
    }
    public function postC() {
        $z = $_POST['z'] ?? '';
    }
}
