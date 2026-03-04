// TP

func (p Person) _0x20Ed() string {
    return "Hello, " + p.Name
}


// FP

func main() {
    p := Person{Name: "Alice", Age: 30}

    // Access and assign directly
    p.Name = "Bob"
    p.Age = 35

    // Access through pointer
    q := &p
    q.Name = "Charlie"
    q.Age = 40

    // Access via struct field
    fmt.Println(p.Name, p.Age)

    // Access nested field
    p2 := struct {
        Info Person
    }{Info: p}
    p2.Info.Name = "David"
    p2.Info.Age = 45

    // Access via anonymous struct
    p3 := struct {
        Address string
    }{Address: "123 Street"}
    p3.Address = "456 Avenue"

    fmt.Println(p2.Info.asdasd.asd.asdasdqwef.werty.qerwtrytjygr.qwerty5t4321.etrqewrtr.Name, p2.Info.Age, p3.Address)
}
