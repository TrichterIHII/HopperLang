// (c) Copyright TrichterIH
// HopperLang -> C++ Compiler
#include <iostream>
#include <fstream>
#include <string>
#include <cctype>
#include <vector>
#include <map>
#include <memory>
#include <sstream>

enum TokenType {
    INT, STRING, BOOLEAN, FLOAT, DOUBLE, LONG, 
    HASHMAP, OBJECT,
    OPEN_BRACKET, CLOSE_BRACKET, OPEN_PAREN, CLOSE_PAREN, OPEN_BRACE, CLOSE_BRACE, 
    IDENT, NUMBER, HEX_NUMBER, STRING_LITERAL,
    PLUS, MULTI, EQUAL, HIGHER, LOWER, 
    PRINT, 
    HASH, QUOTE, DOUBLE_QUOTE, DOT, COMMA, SEMICOLON, STAR, END, INVALID
};

std::string tokenTypeToCppType(TokenType t) {
    switch (t) {
        case TokenType::INT:     return "int";
        case TokenType::STRING:  return "std::string";
        case TokenType::BOOLEAN: return "bool";
        case TokenType::LONG:    return "long";
        case TokenType::FLOAT:   return "float";
        case TokenType::DOUBLE:  return "double";
        default:                 return "auto";
    }
}

struct Token {
    TokenType type;
    std::string text;
};

// Code generation context
struct CodeGen {
    std::stringstream code;
    int indent = 0;
    
    void writeIndent() {
        for (int i = 0; i < indent; i++) code << "    ";
    }
    
    void writeLine(const std::string& line) {
        writeIndent();
        code << line << "\n";
    }
};

struct Expr {
    virtual ~Expr() = default;
    virtual std::string generateCode(CodeGen& gen) = 0;
};

struct NumberExpr : Expr {
    int value;
    NumberExpr(int v) : value(v) {}
    
    std::string generateCode(CodeGen& gen) override {
        return std::to_string(value);
    }
};

struct StringLiteralExpr : Expr {
    std::string value;
    StringLiteralExpr(const std::string& v) : value(v) {}
    
    std::string generateCode(CodeGen& gen) override {
        return "std::string(\"" + value + "\")";
    }
};

struct IdentExpr : Expr {
    std::string name;
    IdentExpr(const std::string& n) : name(n) {}
    
    std::string generateCode(CodeGen& gen) override {
        return name;
    }
};

struct BinaryExpr : Expr {
    std::unique_ptr<Expr> left;
    std::unique_ptr<Expr> right;
    TokenType op;
    
    BinaryExpr(Expr* l, Expr* r, TokenType o) : left(l), right(r), op(o) {}
    
    std::string generateCode(CodeGen& gen) override {
        std::string l = left->generateCode(gen);
        std::string r = right->generateCode(gen);
        
        switch(op) {
            case PLUS: return "(" + l + " + " + r + ")";
            case MULTI: return "(" + l + " * " + r + ")";
            case HIGHER: return "(" + l + " > " + r + ")";
            case LOWER: return "(" + l + " < " + r + ")";
            default: return "(" + l + " OP " + r + ")";
        }
    }
};

struct MemberAccessExpr : Expr {
    std::string objectName;
    std::string memberName;
    
    MemberAccessExpr(const std::string& obj, const std::string& mem) 
        : objectName(obj), memberName(mem) {}
    
    std::string generateCode(CodeGen& gen) override {
        // Handle to_s conversion
        if (memberName == "to_s") {
            return "std::to_string(" + objectName + ")";
        }
        return objectName + "." + memberName;
    }
};

struct ObjectLiteralExpr : Expr {
    std::map<std::string, std::pair<TokenType, std::unique_ptr<Expr>>> fields;
    std::string structName;
    
    std::string generateCode(CodeGen& gen) override {
        std::string code = "{ ";
        bool first = true;

        for (auto& field : fields) {
            if (!first) code += ", ";
            first = false;

            Expr* expr = field.second.second.get();
            if (expr) {
                code += expr->generateCode(gen);
            } else {
                // Default values based on type
                TokenType type = field.second.first;
                switch(type) {
                    case INT: code += "0"; break;
                    case STRING: code += "\"\""; break;
                    case BOOLEAN: code += "false"; break;
                    case FLOAT: code += 0.0f; break;
                    case DOUBLE: code += "0.0"; break;
                    default: code += "0"; break;
                }
            }
        }
        code += " }";
        return code;
    }
};

struct HashmapLiteralExpr : Expr {
    std::string generateCode(CodeGen& gen) override {
        return "std::map<int, int>()"; // Placeholder
    }
};

struct Statement {
    virtual ~Statement() = default;
    virtual void generateCode(CodeGen& gen) = 0;
};

struct Declaration : Statement {
    TokenType type;
    std::string name;
    std::unique_ptr<Expr> initExpr;

    Declaration(TokenType t, const std::string& n, Expr* expr)
        : type(t), name(n), initExpr(expr) {}
    
    void generateCode(CodeGen& gen) override {

    // --- OBJECT Sonderfall ---
    if (type == OBJECT) {
        auto* obj = dynamic_cast<ObjectLiteralExpr*>(initExpr.get());
        if (!obj) return;

        // Struct-Name festlegen
        obj->structName = name + "_t";

        // Struct-Definition
        gen.code << "struct " << obj->structName << " {\n";
        for (auto& field : obj->fields) {
            gen.code << "    "
                     << tokenTypeToCppType(field.second.first)
                     << " "
                     << field.first
                     << ";\n";
        }
        gen.code << "};\n\n";

        // Variable deklarieren
        gen.writeLine(obj->structName + " " + name + " = " +
                      obj->generateCode(gen) + ";");
        return;
    }

    // --- normale Typen ---
    std::string cppType;
    switch(type) {
        case INT: cppType = "int"; break;
        case STRING: cppType = "std::string"; break;
        case BOOLEAN: cppType = "bool"; break;
        case FLOAT: cppType = "float"; break;
        case DOUBLE: cppType = "double"; break;
        case LONG: cppType = "long"; break;
        case HASHMAP: cppType = "std::map<int, int>"; break;
        default: cppType = "auto"; break;
    }

    if (initExpr) {
        gen.writeLine(cppType + " " + name + " = " +
                      initExpr->generateCode(gen) + ";");
    } else {
        gen.writeLine(cppType + " " + name + " = {};");
    }
}

};

struct AssignmentStatement : Statement {
    std::string objectName;
    std::string memberName;
    std::unique_ptr<Expr> valueExpr;
    
    AssignmentStatement(const std::string& obj, const std::string& mem, Expr* expr)
        : objectName(obj), memberName(mem), valueExpr(expr) {}
    
    void generateCode(CodeGen& gen) override {
        if (valueExpr) {
            gen.writeLine(objectName + "." + memberName + " = " + valueExpr->generateCode(gen) + ";");
        }
    }
};

struct PrintStatement : Statement {
    std::unique_ptr<Expr> expr;
    
    PrintStatement(Expr* e) : expr(e) {}
    
    void generateCode(CodeGen& gen) override {
        if (expr) {
            gen.writeLine("std::cout << " + expr->generateCode(gen) + " << std::endl;");
        }
    }
};

struct ScanStatement : Statement {
    std::string variableName;
    
    ScanStatement(const std::string& varName) : variableName(varName) {}
    
    void generateCode(CodeGen& gen) override {
        gen.writeLine("std::cout << \"> \" << std::flush;");
        gen.writeLine("std::getline(std::cin, " + variableName + "_input);");
        gen.writeLine(variableName + " = std::stoi(" + variableName + "_input);");
        // We need to declare the input variable at the top of main
    }
};

class Lexer {
    const std::string& input;
    size_t pos = 0;
public:
    Lexer(const std::string& src) : input(src) {}

    Token getNextToken() {
        while (pos < input.size() && isspace(input[pos])) pos++;

        if (pos == input.size()) return {END, ""};

        char c = input[pos];

        // Hex-Zahlen
        if (c == '0' && pos + 1 < input.size() && input[pos + 1] == 'x') {
            pos += 2;
            size_t start = pos;
            while (pos < input.size() && isxdigit(input[pos])) pos++;
            return {HEX_NUMBER, input.substr(start - 2, pos - start + 2)};
        }

        // String-Literale
        if (c == '"') {
            pos++;
            size_t start = pos;
            while (pos < input.size() && input[pos] != '"') pos++;
            std::string str = input.substr(start, pos - start);
            if (pos < input.size()) pos++; // closing "
            return {STRING_LITERAL, str};
        }

        if (isalpha(c)) {
            size_t start = pos;
            while (pos < input.size() && (isalnum(input[pos]) || input[pos] == '_')) pos++;
            std::string word = input.substr(start, pos - start);
            if (word == "int") return {INT, word};
            else if (word == "str") return {STRING, word};
            else if (word == "bool") return {BOOLEAN, word};
            else if (word == "float") return {FLOAT, word};
            else if (word == "double") return {DOUBLE, word};
            else if (word == "long") return {LONG, word};
            else if (word == "hashmap") return {HASHMAP, word};
            else if (word == "object") return {OBJECT, word};
            else if (word == "print") return {PRINT, word};
            else return {IDENT, word};
        }

        if (isdigit(c)) {
            size_t start = pos;
            while (pos < input.size() && isdigit(input[pos])) pos++;
            return {NUMBER, input.substr(start, pos - start)};
        }

        pos++;
        switch(c) {
            case '+': return {PLUS, "+"};
            case '*': return {STAR, "*"};
            case '=': return {EQUAL, "="};
            case '(': return {OPEN_PAREN, "("};
            case ')': return {CLOSE_PAREN, ")"};
            case '[': return {OPEN_BRACKET, "["};
            case ']': return {CLOSE_BRACKET, "]"};
            case '{': return {OPEN_BRACE, "{"};
            case '}': return {CLOSE_BRACE, "}"};
            case '>': return {HIGHER, ">"};
            case '<': return {LOWER, "<"};
            case '#': return {HASH, "#"};
            case '\'': return {QUOTE, "\'"};
            case '.': return {DOT, "."};
            case ',': return {COMMA, ","};
            case ';': return {SEMICOLON, ";"};
            default: return {INVALID, std::string(1, c)};
        }
    }
};

class Parser {
    Lexer& lexer;
    Token currentToken;

    void nextToken() {
        currentToken = lexer.getNextToken();
    }

    Expr* parsePrimary() {
        if (currentToken.type == NUMBER) {
            int val = std::stoi(currentToken.text);
            nextToken();
            return new NumberExpr(val);
        }
        
        if (currentToken.type == HEX_NUMBER) {
            int val = std::stoi(currentToken.text, nullptr, 16);
            nextToken();
            return new NumberExpr(val);
        }
        
        if (currentToken.type == STRING_LITERAL) {
            std::string val = currentToken.text;
            nextToken();
            return new StringLiteralExpr(val);
        }
        
        if (currentToken.type == IDENT) {
            std::string name = currentToken.text;
            nextToken();
            
            // Member access
            if (currentToken.type == DOT) {
                nextToken();
                if (currentToken.type == IDENT) {
                    std::string member = currentToken.text;
                    nextToken();
                    return new MemberAccessExpr(name, member);
                }
            }
            
            return new IdentExpr(name);
        }
        
        if (currentToken.type == OPEN_PAREN) {
            nextToken();
            Expr* expr = parseExpr();
            if (currentToken.type == CLOSE_PAREN) {
                nextToken();
            }
            return expr;
        }
        
        // Object literal
        if (currentToken.type == OPEN_BRACE) {
            return parseObjectLiteral();
        }
        
        return nullptr;
    }

    Expr* parseMultiplicative() {
        Expr* left = parsePrimary();
        
        while (currentToken.type == STAR) {
            TokenType op = currentToken.type;
            nextToken();
            Expr* right = parsePrimary();
            left = new BinaryExpr(left, right, op);
        }
        
        return left;
    }

    Expr* parseAdditive() {
        Expr* left = parseMultiplicative();
        
        while (currentToken.type == PLUS) {
            TokenType op = currentToken.type;
            nextToken();
            Expr* right = parseMultiplicative();
            left = new BinaryExpr(left, right, op);
        }
        
        return left;
    }

    Expr* parseComparison() {
        Expr* left = parseAdditive();
        
        while (currentToken.type == HIGHER || currentToken.type == LOWER) {
            TokenType op = currentToken.type;
            nextToken();
            Expr* right = parseAdditive();
            left = new BinaryExpr(left, right, op);
        }
        
        return left;
    }

    Expr* parseExpr() {
        return parseComparison();
    }

    Expr* parseObjectLiteral() {
        if (currentToken.type != OPEN_BRACE) return nullptr;
        nextToken();
        
        auto obj = new ObjectLiteralExpr();
        
        while (currentToken.type != CLOSE_BRACE && currentToken.type != END) {
            // Check if it's a type keyword (for object fields)
            if (currentToken.type == INT || currentToken.type == STRING || 
                currentToken.type == BOOLEAN || currentToken.type == FLOAT ||
                currentToken.type == DOUBLE || currentToken.type == LONG) {
                
                TokenType fieldType = currentToken.type;
                nextToken();
                
                if (currentToken.type != IDENT) break;
                std::string fieldName = currentToken.text;
                nextToken();
                
                Expr* fieldValue = nullptr;
                if (currentToken.type == EQUAL) {
                    nextToken();
                    fieldValue = parseExpr();
                }
                
                obj->fields[fieldName] = {fieldType, std::unique_ptr<Expr>(fieldValue)};
                
                if (currentToken.type == SEMICOLON) {
                    nextToken();
                }
            } else {
                // Skip unknown tokens inside object
                nextToken();
            }
        }
        
        if (currentToken.type == CLOSE_BRACE) {
            nextToken();
        }
        
        return obj;
    }

    Expr* parseHashmapLiteral() {
        // Parse {{...}} hashmap literal
        if (currentToken.type != OPEN_BRACE) return nullptr;
        nextToken();
        
        // Skip entire hashmap content for now
        int braceDepth = 1;
        while (braceDepth > 0 && currentToken.type != END) {
            if (currentToken.type == OPEN_BRACE) braceDepth++;
            if (currentToken.type == CLOSE_BRACE) braceDepth--;
            if (braceDepth > 0) nextToken();
        }
        
        if (currentToken.type == CLOSE_BRACE) {
            nextToken();
        }
        
        return new HashmapLiteralExpr();
    }

    TokenType parseType() {
        TokenType baseType = currentToken.type;
        nextToken();
        
        // Skip array/pointer notation
        while (currentToken.type == STAR || currentToken.type == OPEN_BRACKET) {
            if (currentToken.type == STAR) {
                nextToken();
            } else {
                nextToken(); // [
                // Skip any content inside brackets (like size limits)
                while (currentToken.type != CLOSE_BRACKET && currentToken.type != END) {
                    nextToken();
                }
                if (currentToken.type == CLOSE_BRACKET) {
                    nextToken();
                }
            }
        }
        
        // Skip generics
        if (currentToken.type == LOWER) {
            nextToken();
            parseType();
            if (currentToken.type == HIGHER) {
                nextToken();
            }
        }
        
        return baseType;
    }

    Statement* parseDeclaration() {
        TokenType type = parseType();

        if (currentToken.type != IDENT) {
            std::cerr << "Fehler: erwarteter Bezeichner\n";
            return nullptr;
        }
        std::string name = currentToken.text;
        nextToken();

        Expr* initExpr = nullptr;
        if (currentToken.type == EQUAL) {
            nextToken();
            
            // Check for hashmap literal {{...}}
            if (type == HASHMAP && currentToken.type == OPEN_BRACE) {
                initExpr = parseHashmapLiteral();
            } else {
                initExpr = parseExpr();
            }
        }

        if (currentToken.type != SEMICOLON) {
            std::cerr << "Fehler: erwartetes Semikolon nach Deklaration von '" << name << "'\n";
            std::cerr << "Aktuelles Token: " << currentToken.type << " ('" << currentToken.text << "')\n";
            return nullptr;
        }
        nextToken();

        return new Declaration(type, name, initExpr);
    }

    Statement* parseAssignment() {
        std::string objName = currentToken.text;
        nextToken();
        
        // Check for variable#scan or variable#print
        if (currentToken.type == HASH) {
            nextToken();
            if (currentToken.type == IDENT && currentToken.text == "scan") {
                nextToken();
                if (currentToken.type == SEMICOLON) {
                    nextToken();
                }
                return new ScanStatement(objName);
            }
            // Support variable#print (not just member#print)
            if ((currentToken.type == IDENT && currentToken.text == "print") || currentToken.type == PRINT) {
                nextToken();
                if (currentToken.type == SEMICOLON) {
                    nextToken();
                }
                return new PrintStatement(new IdentExpr(objName));
            }
        }
        
        if (currentToken.type == DOT) {
            nextToken();
            if (currentToken.type != IDENT) return nullptr;
            
            std::string memberName = currentToken.text;
            nextToken();
            
            // Check for #print
            if (currentToken.type == HASH) {
                nextToken();
                // Accept both PRINT token and "print" as IDENT
                if ((currentToken.type == IDENT && currentToken.text == "print") || currentToken.type == PRINT) {
                    nextToken();
                    if (currentToken.type == SEMICOLON) {
                        nextToken();
                    }
                    
                    // Special handling for to_s - print the variable itself as string
                    if (memberName == "to_s") {
                        return new PrintStatement(new IdentExpr(objName));
                    }
                    
                    return new PrintStatement(new MemberAccessExpr(objName, memberName));
                }
            }
            
            // Regular assignment
            if (currentToken.type == EQUAL) {
                nextToken();
                Expr* valueExpr = parseExpr();
                if (currentToken.type == SEMICOLON) {
                    nextToken();
                }
                return new AssignmentStatement(objName, memberName, valueExpr);
            }
        }
        
        return nullptr;
    }

    Statement* parseStatement() {
        if (currentToken.type == PRINT) {
            nextToken();
            Expr* expr = parseExpr();
            if (currentToken.type != SEMICOLON) {
                std::cerr << "Fehler: fehlendes Semikolon bei print\n";
                return nullptr;
            }
            nextToken();
            return new PrintStatement(expr);
        }

        if (currentToken.type == INT || currentToken.type == BOOLEAN 
            || currentToken.type == STRING || currentToken.type == FLOAT
            || currentToken.type == DOUBLE || currentToken.type == LONG
            || currentToken.type == HASHMAP || currentToken.type == OBJECT) {
            return parseDeclaration();
        }

        if (currentToken.type == IDENT) {
            return parseAssignment();
        }

        std::cerr << "Fehler: unbekanntes Statement bei Token: " << currentToken.type << " ('" << currentToken.text << "')\n";
        return nullptr;
    }

public:
    Parser(Lexer& lex) : lexer(lex) {
        nextToken();
    }

    std::vector<std::unique_ptr<Statement>> parseProgram() {
        std::vector<std::unique_ptr<Statement>> stmts;
        while (currentToken.type != END) {
            Statement* stmt = parseStatement();
            if (!stmt) break;
            stmts.push_back(std::unique_ptr<Statement>(stmt));
        }
        return stmts;
    }
};

int main(int argc, char* argv[]) {
    std::cout << "H63 Compiler gestartet\n";
    
    std::string inputPath = "main.h63";
    std::string outputPath = "output.cpp";
    
    // Parse command line arguments
    if (argc > 1) {
        inputPath = argv[1];
    }
    if (argc > 2) {
        outputPath = argv[2];
    }
    
    std::ifstream file(inputPath);
    if (!file) {
        std::cerr << "Fehler: Datei " + inputPath + " nicht gefunden.\n";
        return 1;
    }

    std::string code((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());

    Lexer lexer(code);
    Parser parser(lexer);
    
    auto statements = parser.parseProgram();
    
    std::cout << "Generiere C++ Code...\n";
    
    CodeGen gen;
    
    // Generate C++ preamble
    gen.code << "#include <iostream>\n";
    gen.code << "#include <string>\n";
    gen.code << "#include <map>\n\n";
    gen.code << "int main() {\n";
    gen.indent++;
    
    // Add input variable declaration for scan
    gen.writeLine("std::string alter_input;");
    gen.writeLine("");
    
    // Generate code for each statement
    for (auto& stmt : statements) {
        stmt->generateCode(gen);
    }
    
    gen.indent--;
    gen.code << "    return 0;\n";
    gen.code << "}\n";
    
    // Write to output file
    std::ofstream outFile(outputPath);
    if (!outFile) {
        std::cerr << "Fehler: Kann " << outputPath << " nicht schreiben\n";
        return 1;
    }
    
    outFile << gen.code.str();
    outFile.close();
    
    std::cout << "C++ Code wurde nach " << outputPath << " geschrieben\n";
    std::cout << "\nKompiliere mit:\n";
    std::cout << "  clang++ -std=c++11 -O3 -march=native " << outputPath << " -o program\n";
    std::cout << "  ./program\n";
    
    return 0;
}
