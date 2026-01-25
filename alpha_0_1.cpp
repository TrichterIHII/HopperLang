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

struct Token {
    TokenType type;
    std::string text;
};

// Value types für Runtime
struct Value {
    enum Type { INT_VAL, STRING_VAL, BOOL_VAL, FLOAT_VAL, OBJECT_VAL, HASHMAP_VAL, NONE };
    Type type;
    
    int intVal;
    std::string strVal;
    bool boolVal;
    double floatVal;
    std::map<std::string, Value> objectFields;
    std::map<std::string, Value> hashmapData;
    
    Value() : type(NONE), intVal(0), boolVal(false), floatVal(0.0) {}
    
    std::string toString() const {
        switch(type) {
            case INT_VAL: return std::to_string(intVal);
            case STRING_VAL: return strVal;
            case BOOL_VAL: return boolVal ? "true" : "false";
            case FLOAT_VAL: return std::to_string(floatVal);
            case OBJECT_VAL: return "[object]";
            case HASHMAP_VAL: return "[hashmap]";
            default: return "none";
        }
    }
};

struct Expr {
    virtual ~Expr() = default;
    virtual Value evaluate(std::map<std::string, Value>& env) = 0;
};

struct NumberExpr : Expr {
    int value;
    NumberExpr(int v) : value(v) {}
    Value evaluate(std::map<std::string, Value>& env) override {
        Value v;
        v.type = Value::INT_VAL;
        v.intVal = value;
        return v;
    }
};

struct StringLiteralExpr : Expr {
    std::string value;
    StringLiteralExpr(const std::string& v) : value(v) {}
    Value evaluate(std::map<std::string, Value>& env) override {
        Value v;
        v.type = Value::STRING_VAL;
        v.strVal = value;
        return v;
    }
};

struct IdentExpr : Expr {
    std::string name;
    IdentExpr(const std::string& n) : name(n) {}
    Value evaluate(std::map<std::string, Value>& env) override {
        if (env.find(name) != env.end()) {
            return env[name];
        }
        Value v;
        return v;
    }
};

struct BinaryExpr : Expr {
    std::unique_ptr<Expr> left;
    std::unique_ptr<Expr> right;
    TokenType op;
    
    BinaryExpr(Expr* l, Expr* r, TokenType o) : left(l), right(r), op(o) {}
    
    Value evaluate(std::map<std::string, Value>& env) override {
        Value lval = left->evaluate(env);
        Value rval = right->evaluate(env);
        Value result;
        
        if (op == PLUS) {
            // Integer addition
            if (lval.type == Value::INT_VAL && rval.type == Value::INT_VAL) {
                result.type = Value::INT_VAL;
                result.intVal = lval.intVal + rval.intVal;
            }
            // String concatenation
            else if (lval.type == Value::STRING_VAL || rval.type == Value::STRING_VAL) {
                result.type = Value::STRING_VAL;
                result.strVal = lval.toString() + rval.toString();
            }
        } else if (op == MULTI && lval.type == Value::INT_VAL && rval.type == Value::INT_VAL) {
            result.type = Value::INT_VAL;
            result.intVal = lval.intVal * rval.intVal;
        } else if (op == HIGHER && lval.type == Value::INT_VAL && rval.type == Value::INT_VAL) {
            result.type = Value::BOOL_VAL;
            result.boolVal = lval.intVal > rval.intVal;
        } else if (op == LOWER && lval.type == Value::INT_VAL && rval.type == Value::INT_VAL) {
            result.type = Value::BOOL_VAL;
            result.boolVal = lval.intVal < rval.intVal;
        }
        
        return result;
    }
};

struct MemberAccessExpr : Expr {
    std::string objectName;
    std::string memberName;
    
    MemberAccessExpr(const std::string& obj, const std::string& mem) 
        : objectName(obj), memberName(mem) {}
    
    Value evaluate(std::map<std::string, Value>& env) override {
        if (env.find(objectName) != env.end()) {
            Value& obj = env[objectName];
            
            // Special handling for to_s - convert any value to string
            if (memberName == "to_s") {
                Value result;
                result.type = Value::STRING_VAL;
                result.strVal = obj.toString();
                return result;
            }
            
            // Regular object field access
            if (obj.type == Value::OBJECT_VAL) {
                if (obj.objectFields.find(memberName) != obj.objectFields.end()) {
                    return obj.objectFields[memberName];
                }
            }
        }
        Value v;
        return v;
    }
};

struct ObjectLiteralExpr : Expr {
    std::map<std::string, std::pair<TokenType, std::unique_ptr<Expr>>> fields;
    
    Value evaluate(std::map<std::string, Value>& env) override {
        Value obj;
        obj.type = Value::OBJECT_VAL;
        for (auto& [name, typeAndExpr] : fields) {
            if (typeAndExpr.second) {
                obj.objectFields[name] = typeAndExpr.second->evaluate(env);
            }
        }
        return obj;
    }
};

struct HashmapLiteralExpr : Expr {
    // For now, just a placeholder
    Value evaluate(std::map<std::string, Value>& env) override {
        Value hm;
        hm.type = Value::HASHMAP_VAL;
        return hm;
    }
};

struct Statement {
    virtual ~Statement() = default;
    virtual void execute(std::map<std::string, Value>& env) = 0;
};

struct Declaration : Statement {
    TokenType type;
    std::string name;
    std::unique_ptr<Expr> initExpr;

    Declaration(TokenType t, const std::string& n, Expr* expr)
        : type(t), name(n), initExpr(expr) {}
    
    void execute(std::map<std::string, Value>& env) override {
        if (initExpr) {
            env[name] = initExpr->evaluate(env);
        } else {
            // Create empty value with correct type
            Value v;
            if (type == INT) {
                v.type = Value::INT_VAL;
                v.intVal = 0;
            } else if (type == STRING) {
                v.type = Value::STRING_VAL;
                v.strVal = "";
            } else if (type == BOOLEAN) {
                v.type = Value::BOOL_VAL;
                v.boolVal = false;
            } else if (type == FLOAT || type == DOUBLE) {
                v.type = Value::FLOAT_VAL;
                v.floatVal = 0.0;
            } else if (type == HASHMAP) {
                v.type = Value::HASHMAP_VAL;
            } else if (type == OBJECT) {
                v.type = Value::OBJECT_VAL;
            }
            env[name] = v;
        }
    }
};

struct AssignmentStatement : Statement {
    std::string objectName;
    std::string memberName;
    std::unique_ptr<Expr> valueExpr;
    
    AssignmentStatement(const std::string& obj, const std::string& mem, Expr* expr)
        : objectName(obj), memberName(mem), valueExpr(expr) {}
    
    void execute(std::map<std::string, Value>& env) override {
        if (env.find(objectName) != env.end()) {
            Value& obj = env[objectName];
            if (obj.type == Value::OBJECT_VAL && valueExpr) {
                obj.objectFields[memberName] = valueExpr->evaluate(env);
            }
        }
    }
};

struct PrintStatement : Statement {
    std::unique_ptr<Expr> expr;
    bool useToString;
    
    PrintStatement(Expr* e, bool toString = false) : expr(e), useToString(toString) {}
    
    void execute(std::map<std::string, Value>& env) override {
        if (expr) {
            Value val = expr->evaluate(env);
            std::cout << val.toString() << std::endl;
        }
    }
};

struct ScanStatement : Statement {
    std::string variableName;
    
    ScanStatement(const std::string& varName) : variableName(varName) {}
    
    void execute(std::map<std::string, Value>& env) override {
        std::string input;
        std::cout << "> " << std::flush;  // Eingabeaufforderung
        std::getline(std::cin, input);
        
        // Check if variable exists in environment
        if (env.find(variableName) != env.end()) {
            Value& var = env[variableName];
            
            // Parse input based on variable type
            if (var.type == Value::INT_VAL) {
                try {
                    var.intVal = std::stoi(input);
                } catch (...) {
                    std::cerr << "Fehler: Ungültige Ganzzahl\n";
                }
            } else if (var.type == Value::STRING_VAL) {
                var.strVal = input;
            } else if (var.type == Value::BOOL_VAL) {
                var.boolVal = (input == "true" || input == "1");
            } else if (var.type == Value::FLOAT_VAL) {
                try {
                    var.floatVal = std::stod(input);
                } catch (...) {
                    std::cerr << "Fehler: Ungültige Fließkommazahl\n";
                }
            } else {
                // Default: treat as string
                var.type = Value::STRING_VAL;
                var.strVal = input;
            }
        } else {
            std::cerr << "Fehler: Variable '" << variableName << "' nicht gefunden\n";
        }
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
        
        // DO NOT consume semicolon here - it belongs to the declaration statement
        
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

int main() {
    std::cout << "H63 Interpreter gestartet\n";
    std::string path = "main.h63";
    std::ifstream file(path);
    if (!file) {
        std::cerr << "Datei " + path + " nicht gefunden.\n";
        return 1;
    }

    std::string code((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());

    Lexer lexer(code);
    Parser parser(lexer);
    
    auto statements = parser.parseProgram();
    
    std::cout << "\n=== Ausfuehrung ===\n";
    std::map<std::string, Value> environment;
    
    for (auto& stmt : statements) {
        stmt->execute(environment);
    }

    return 0;
}
