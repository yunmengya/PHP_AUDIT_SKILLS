// TP

if true {
    fmt.Println("Condition is true")
}

func x() {
    a := 1
    switch 2 {
    case 3:
        fmt.Println("1")
    default:
        fmt.Println("Invalid")
    }
}


// FP

name := "Go"
if name == "Go" {
    fmt.Println("Hello, Go!")
}

words := []string{"apple", "banana", "cherry"}
for _, word := range words {
    fmt.Println(word)
}
