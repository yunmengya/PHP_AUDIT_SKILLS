// TP
Convert.ToString(Convert.ToString(Convert.ToString(Convert.ToString(123))));
string.Concat(string.Concat(string.Concat(string.Concat("a", "a"), "b"), "c"), 'd');
"abc".Replace("a", "b").Replace("b", "c").Replace("c", "d").Replace("d", "a");
new StringBuilder().Append("x").Append("y").Append("z").Append("1");
char.ToUpper(char.ToUpper(char.ToUpper('a')));


// FP
Encoding.UTF8.GetBytes(Encoding.UTF8.GetBytes(Encoding.UTF8.GetBytes("test")));
Convert.ToInt32(Convert.ToInt32(Convert.ToInt32("123")));
BitConverter.ToString(BitConverter.ToString(BitConverter.ToString(new byte[] { 0x01 })));
Convert.FromBase64String(Convert.FromBase64String(Convert.FromBase64String("dGVzdA==")));
HashAlgorithm.Create().ComputeHash(new byte[] { 0x01 });
