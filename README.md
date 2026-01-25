# HopperLang
A Coding Language made for Programmers. Try it out and LOVE it!

# How to use it
Create a filee main.h63 in the same directory where the main.cpp is. 

The following example contains every feature of the Alpha0.1 version:

int a = 1 + 2; 
bool b = 4 > 8;
hashmap*****<str> c;
hashmap[][][][][]<int> d = {{(8,7,9,90,0), 0x64}, {(9,9,9,9,9), 5}};
object e = {
    int id = 6543;
    str name = "moinsen";
};

e.id = 5;
e.name#print;

a.to_s#print;

int alter;
alter#scan;
str output = "Deine eingabe ist: " + alter.to_s;
output#print;

I think you understand the first two lines. The following two lines are a little uncommon. In line 3 we have a hashmap with five dimensions and it contains strings. In the fourth line we have also a 5 dimensional hashmap, but it contains integers and habe brackets instead of stars. The idea of this is, that the stars are the short variante to define a 5D hashmap. But in the brackets, you can define the size of every dimension. In the angle brackets we have the datatype the hashmap contains, and after that we can set a name for the hashmap. You can set a valur in {} and in () is the key: {(key), value}. 
Now we habe an Object. The syntax of objects in HopperLang is very common and similar to many other languages. After creating the object, we access to the variables in it. 
After that you can see a example for print. Directly integradet methods, you can access with arg#method; or #method;. 
Same thing with #scan. with arg#scan; you can do a cin << arg(cpp). In the end there is a small example for inputs and prints. 
