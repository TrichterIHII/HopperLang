// (c) Copyright TrichterIH
// HopperLang Compiler v1.0.0
// HopperLang (.hpl) -> Native Code Compiler (via LLVM)
// Requires C++17
#include <iostream>
#include <fstream>
#include <string>
#include <cctype>
#include <vector>
#include <map>
#include <memory>
#include <sstream>

// LLVM Headers
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/Host.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/IR/LegacyPassManager.h"

using namespace llvm;

enum TokenType {
    INT, STRING, BOOLEAN, FLOAT, DOUBLE, LONG, 
    HASHMAP, OBJECT,
    OPEN_BRACKET, CLOSE_BRACKET, OPEN_PAREN, CLOSE_PAREN, OPEN_BRACE, CLOSE_BRACE, 
    IDENT, NUMBER, HEX_NUMBER, STRING_LITERAL, 
    PLUS, MULTI, EQUAL, HIGHER, LOWER, BACKSLASH, DOLLAR, ELLIPSIS, 
    IF, WHILE, TIMES, RETURN, 
    PRINT, 
    HASH, QUOTE, DOUBLE_QUOTE, DOT, COMMA, SEMICOLON, STAR, END, INVALID
};

struct Token {
    TokenType type;
    std::string text;
};

// LLVM Code Generator
class LLVMCodeGen {
public:
    LLVMContext context;
    std::unique_ptr<Module> module;
    IRBuilder<> builder;
    
    Function* mainFunc;
    Function* printfFunc;
    Function* scanfFunc;
    Function* exitFunc;
    Function* sprintfFunc;
    Function* strcatFunc;
    Function* mallocFunc;
    
    std::map<std::string, AllocaInst*> namedValues;
    std::map<std::string, StructType*> structTypes;
    std::map<std::string, std::map<std::string, unsigned>> structFieldIndices;
    
    LLVMCodeGen(const std::string& moduleName) 
        : builder(context), module(new Module(moduleName, context)) {
        
        // Declare printf
        std::vector<Type*> printfArgs;
        printfArgs.push_back(builder.getInt8PtrTy());
        FunctionType* printfType = FunctionType::get(builder.getInt32Ty(), printfArgs, true);
        printfFunc = Function::Create(printfType, Function::ExternalLinkage, "printf", module.get());
        
        // Declare scanf
        std::vector<Type*> scanfArgs;
        scanfArgs.push_back(builder.getInt8PtrTy());
        FunctionType* scanfType = FunctionType::get(builder.getInt32Ty(), scanfArgs, true);
        scanfFunc = Function::Create(scanfType, Function::ExternalLinkage, "scanf", module.get());
        
        // Declare exit
        std::vector<Type*> exitArgs;
        exitArgs.push_back(builder.getInt32Ty());
        FunctionType* exitType = FunctionType::get(builder.getVoidTy(), exitArgs, false);
        exitFunc = Function::Create(exitType, Function::ExternalLinkage, "exit", module.get());
        
        // Declare sprintf
        std::vector<Type*> sprintfArgs;
        sprintfArgs.push_back(builder.getInt8PtrTy());
        sprintfArgs.push_back(builder.getInt8PtrTy());
        FunctionType* sprintfType = FunctionType::get(builder.getInt32Ty(), sprintfArgs, true);
        sprintfFunc = Function::Create(sprintfType, Function::ExternalLinkage, "sprintf", module.get());
        
        // Declare strcat
        std::vector<Type*> strcatArgs;
        strcatArgs.push_back(builder.getInt8PtrTy());
        strcatArgs.push_back(builder.getInt8PtrTy());
        FunctionType* strcatType = FunctionType::get(builder.getInt8PtrTy(), strcatArgs, false);
        strcatFunc = Function::Create(strcatType, Function::ExternalLinkage, "strcat", module.get());
        
        // Declare malloc
        std::vector<Type*> mallocArgs;
        mallocArgs.push_back(builder.getInt64Ty());
        FunctionType* mallocType = FunctionType::get(builder.getInt8PtrTy(), mallocArgs, false);
        mallocFunc = Function::Create(mallocType, Function::ExternalLinkage, "malloc", module.get());
        
        // Create main function
        FunctionType* mainType = FunctionType::get(builder.getInt32Ty(), false);
        mainFunc = Function::Create(mainType, Function::ExternalLinkage, "main", module.get());
        BasicBlock* entry = BasicBlock::Create(context, "entry", mainFunc);
        builder.SetInsertPoint(entry);
    }

    Function* currentFunction;  // Aktuelle Funktion (für return)
    
    // Neue Funktion: Alloca in Funktions-Entry-Block
    AllocaInst* createFunctionBlockAlloca(const std::string& varName, Type* type, Function* func) {
        IRBuilder<> tmpBuilder(&func->getEntryBlock(), func->getEntryBlock().begin());
        return tmpBuilder.CreateAlloca(type, nullptr, varName);
    }
    
    // Alle Funktionen generieren
    void generateFunctions(std::vector<std::unique_ptr<FunctionDecl>>& functions) {
        for (auto& func : functions) {
            func->codegen(*this);
        }
    }
    
    AllocaInst* createEntryBlockAlloca(const std::string& varName, Type* type) {
        IRBuilder<> tmpBuilder(&mainFunc->getEntryBlock(), mainFunc->getEntryBlock().begin());
        return tmpBuilder.CreateAlloca(type, nullptr, varName);
    }
    
    Value* createGlobalString(const std::string& str) {
        return builder.CreateGlobalStringPtr(str);
    }
    
    // String concatenation helper
    Value* concatStrings(Value* str1, Value* str2) {
        // Allocate buffer (1024 bytes should be enough)
        Value* bufferSize = builder.getInt64(1024);
        Value* buffer = builder.CreateCall(mallocFunc, {bufferSize}, "strbuf");
        
        // Copy first string
        builder.CreateCall(sprintfFunc, {buffer, createGlobalString("%s"), str1});
        
        // Concatenate second string
        builder.CreateCall(strcatFunc, {buffer, str2});
        
        return buffer;
    }
    
    // Convert int to string
    Value* intToString(Value* intVal) {
        Value* bufferSize = builder.getInt64(32);
        Value* buffer = builder.CreateCall(mallocFunc, {bufferSize}, "intbuf");
        builder.CreateCall(sprintfFunc, {buffer, createGlobalString("%d"), intVal});
        return buffer;
    }
    
    void finish() {
        builder.CreateRet(builder.getInt32(0));
    }
    
    void print() {
        module->print(outs(), nullptr);
    }
    
    bool verify() {
        std::string err;
        raw_string_ostream errStream(err);
        if (verifyModule(*module, &errStream)) {
            errs() << "Error verifying module: " << err << "\n";
            return false;
        }
        return true;
    }
    
    bool emitObjectFile(const std::string& filename) {
        InitializeAllTargetInfos();
        InitializeAllTargets();
        InitializeAllTargetMCs();
        InitializeAllAsmParsers();
        InitializeAllAsmPrinters();
        
        std::string targetTriple = sys::getDefaultTargetTriple();
        module->setTargetTriple(targetTriple);
        
        std::string error;
        const Target* target = TargetRegistry::lookupTarget(targetTriple, error);
        
        if (!target) {
            errs() << error;
            return false;
        }
        
        TargetOptions opt;
        TargetMachine* targetMachine = target->createTargetMachine(
            targetTriple, "generic", "", opt, Reloc::PIC_);
        
        module->setDataLayout(targetMachine->createDataLayout());
        
        std::error_code EC;
        raw_fd_ostream dest(filename, EC);
        
        if (EC) {
            errs() << "Could not open file: " << EC.message();
            return false;
        }
        
        legacy::PassManager pass;
        
        if (targetMachine->addPassesToEmitFile(pass, dest, nullptr, CGFT_ObjectFile)) {
            errs() << "TargetMachine can't emit a file of this type";
            return false;
        }
        
        pass.run(*module);
        dest.flush();
        
        delete targetMachine;
        return true;
    }
};

enum class ExprKind {
    Number,
    String,
    Ident,
    Binary,
    MemberAccess,
    ObjectLiteral,
    HashmapLiteral,
    Call
};

struct FunctionDecl;

struct Expr {
    ExprKind kind;
    explicit Expr(ExprKind k) : kind(k) {}
    virtual ~Expr() = default;
    virtual Value* codegen(LLVMCodeGen& gen) = 0;
};

struct NumberExpr : Expr {
    int value;
    NumberExpr(int v) : Expr(ExprKind::Number), value(v) {}

    Value* codegen(LLVMCodeGen& gen) override {
        return gen.builder.getInt32(value);
    }
};

struct StringLiteralExpr : Expr {
    std::string value;
    StringLiteralExpr(const std::string& v)
        : Expr(ExprKind::String), value(v) {}

    Value* codegen(LLVMCodeGen& gen) override {
        return gen.createGlobalString(value);
    }
};

struct IdentExpr : Expr {
    std::string name;
    IdentExpr(const std::string& n)
        : Expr(ExprKind::Ident), name(n) {}
    
    Value* codegen(LLVMCodeGen& gen) override {
        AllocaInst* alloca = gen.namedValues[name];
        if (!alloca) {
            std::cerr << "Unknown variable: " << name << "\n";
            return nullptr;
        }
        return gen.builder.CreateLoad(alloca->getAllocatedType(), alloca, name);
    }
};

struct BinaryExpr : Expr {
    std::unique_ptr<Expr> left;
    std::unique_ptr<Expr> right;
    TokenType op;
    
    BinaryExpr(Expr* l, Expr* r, TokenType o)
        : Expr(ExprKind::Binary), left(l), right(r), op(o) {}
    
    Value* codegen(LLVMCodeGen& gen) override {
        Value* l = left->codegen(gen);
        Value* r = right->codegen(gen);
        
        if (!l || !r) return nullptr;
        
        switch(op) {
            case PLUS:
                // Check if string concatenation
                if (l->getType()->isPointerTy() && r->getType()->isPointerTy()) {
                    return gen.concatStrings(l, r);
                }
                return gen.builder.CreateAdd(l, r, "addtmp");
            case MULTI: return gen.builder.CreateMul(l, r, "multmp");
            case HIGHER: return gen.builder.CreateICmpSGT(l, r, "cmptmp");
            case LOWER: return gen.builder.CreateICmpSLT(l, r, "cmptmp");
            default: return nullptr;
        }
    }
};

struct MemberAccessExpr : Expr {
    std::string objectName;
    std::string memberName;
    
    MemberAccessExpr(const std::string& obj, const std::string& mem)
    : Expr(ExprKind::MemberAccess),
      objectName(obj), memberName(mem) {}
    
    Value* codegen(LLVMCodeGen& gen) override {
        // Handle to_s conversion
        if (memberName == "to_s") {
            AllocaInst* alloca = gen.namedValues[objectName];
            if (!alloca) return nullptr;
            Value* val = gen.builder.CreateLoad(alloca->getAllocatedType(), alloca, objectName);
            
            // Convert to string
            if (val->getType()->isIntegerTy()) {
                return gen.intToString(val);
            }
            return val;
        }
        
        // Get the struct pointer
        AllocaInst* structPtr = gen.namedValues[objectName];
        if (!structPtr) return nullptr;
        
        Type* structPtrType = structPtr->getAllocatedType();
        if (!structPtrType->isStructTy()) return nullptr;
        
        std::string structTypeName = objectName + "_t";
        if (gen.structFieldIndices.find(structTypeName) == gen.structFieldIndices.end()) {
            return nullptr;
        }
        
        unsigned fieldIdx = gen.structFieldIndices[structTypeName][memberName];
        
        Value* zero = gen.builder.getInt32(0);
        Value* idx = gen.builder.getInt32(fieldIdx);
        Value* fieldPtr = gen.builder.CreateInBoundsGEP(structPtrType, structPtr, {zero, idx}, memberName);
        
        StructType* st = dyn_cast<StructType>(structPtrType);
        Type* fieldType = st->getElementType(fieldIdx);
        return gen.builder.CreateLoad(fieldType, fieldPtr, memberName);
    }
};

struct ObjectLiteralExpr : Expr {
    ObjectLiteralExpr() : Expr(ExprKind::ObjectLiteral) {}
    std::map<std::string, std::pair<TokenType, std::unique_ptr<Expr>>> fields;
    std::string structName;
    
    Value* codegen(LLVMCodeGen& gen) override {
        StructType* st = gen.structTypes[structName];
        if (!st) return nullptr;
        
        AllocaInst* tempStruct = gen.createEntryBlockAlloca("temp_obj", st);
        
        unsigned idx = 0;
        for (auto& field : fields) {
            Value* zero = gen.builder.getInt32(0);
            Value* fieldIdx = gen.builder.getInt32(idx);
            Value* fieldPtr = gen.builder.CreateInBoundsGEP(st, tempStruct, {zero, fieldIdx}, field.first);
            
            Value* fieldValue = nullptr;
            if (field.second.second) {
                fieldValue = field.second.second->codegen(gen);
            } else {
                switch(field.second.first) {
                    case INT: fieldValue = gen.builder.getInt32(0); break;
                    case LONG: fieldValue = gen.builder.getInt64(0); break;
                    case FLOAT: fieldValue = ConstantFP::get(gen.builder.getFloatTy(), 0.0); break;
                    case DOUBLE: fieldValue = ConstantFP::get(gen.builder.getDoubleTy(), 0.0); break;
                    case BOOLEAN: fieldValue = gen.builder.getInt1(false); break;
                    case STRING: fieldValue = gen.createGlobalString(""); break;
                    default: fieldValue = gen.builder.getInt32(0); break;
                }
            }
            
            if (fieldValue) {
                gen.builder.CreateStore(fieldValue, fieldPtr);
            }
            idx++;
        }
        
        return gen.builder.CreateLoad(st, tempStruct, "obj_val");
    }
};

struct Statement {
    virtual ~Statement() = default;
    virtual void codegen(LLVMCodeGen& gen) = 0;
};

struct Declaration : Statement {
    TokenType type;
    std::string name;
    std::unique_ptr<Expr> initExpr;

    Declaration(TokenType t, const std::string& n, Expr* expr)
        : type(t), name(n), initExpr(expr) {}
    
    void codegen(LLVMCodeGen& gen) override {
        if (type == OBJECT) {
            if (!initExpr || initExpr->kind != ExprKind::ObjectLiteral) {
                return;
            }

            auto* obj = static_cast<ObjectLiteralExpr*>(initExpr.get());
            obj->structName = name + "_t";

            std::vector<Type*> fieldTypes;
            unsigned idx = 0;
            
            for (auto& field : obj->fields) {
                gen.structFieldIndices[obj->structName][field.first] = idx++;
                
                Type* llvmType = nullptr;
                switch(field.second.first) {
                    case INT: llvmType = gen.builder.getInt32Ty(); break;
                    case LONG: llvmType = gen.builder.getInt64Ty(); break;
                    case FLOAT: llvmType = gen.builder.getFloatTy(); break;
                    case DOUBLE: llvmType = gen.builder.getDoubleTy(); break;
                    case BOOLEAN: llvmType = gen.builder.getInt1Ty(); break;
                    case STRING: llvmType = gen.builder.getInt8PtrTy(); break;
                    default: llvmType = gen.builder.getInt32Ty(); break;
                }
                fieldTypes.push_back(llvmType);
            }

            StructType* st = StructType::create(gen.context, fieldTypes, obj->structName);
            gen.structTypes[obj->structName] = st;

            AllocaInst* alloca = gen.createEntryBlockAlloca(name, st);
            gen.namedValues[name] = alloca;

            Value* structVal = obj->codegen(gen);
            if (structVal) {
                gen.builder.CreateStore(structVal, alloca);
            }
            return;
        }

        Type* llvmType = nullptr;
        switch(type) {
            case INT: llvmType = gen.builder.getInt32Ty(); break;
            case LONG: llvmType = gen.builder.getInt64Ty(); break;
            case FLOAT: llvmType = gen.builder.getFloatTy(); break;
            case DOUBLE: llvmType = gen.builder.getDoubleTy(); break;
            case BOOLEAN: llvmType = gen.builder.getInt1Ty(); break;
            case STRING: llvmType = gen.builder.getInt8PtrTy(); break;
            case HASHMAP: llvmType = gen.builder.getInt32Ty(); break;
            default: llvmType = gen.builder.getInt32Ty(); break;
        }

        AllocaInst* alloca = gen.createEntryBlockAlloca(name, llvmType);
        gen.namedValues[name] = alloca;

        if (initExpr) {
            Value* initVal = initExpr->codegen(gen);
            if (initVal) {
                gen.builder.CreateStore(initVal, alloca);
            }
        } else {
            Value* defaultVal = nullptr;
            switch(type) {
                case INT: defaultVal = gen.builder.getInt32(0); break;
                case LONG: defaultVal = gen.builder.getInt64(0); break;
                case FLOAT: defaultVal = ConstantFP::get(gen.builder.getFloatTy(), 0.0); break;
                case DOUBLE: defaultVal = ConstantFP::get(gen.builder.getDoubleTy(), 0.0); break;
                case BOOLEAN: defaultVal = gen.builder.getInt1(false); break;
                case STRING: defaultVal = gen.createGlobalString(""); break;
                default: defaultVal = gen.builder.getInt32(0); break;
            }
            if (defaultVal) {
                gen.builder.CreateStore(defaultVal, alloca);
            }
        }
    }
};

// Parameter-Info
struct Parameter {
    TokenType type;
    std::string name;
    bool isVarArgs;  // für int... values
};

// Funktions-Deklaration
struct FunctionDecl {
    TokenType returnType;
    std::string name;
    std::vector<Parameter> parameters;
    std::vector<std::unique_ptr<Statement>> body;
    
    Function* codegen(LLVMCodeGen& gen) {
        // 1. Parameter-Typen sammeln
        std::vector<Type*> paramTypes;
        for (auto& param : parameters) {
            if (param.isVarArgs) {
                // Varargs = Pointer + Länge
                paramTypes.push_back(gen.builder.getInt32Ty());  // Array
                paramTypes.push_back(gen.builder.getInt32Ty());     // Länge
            } else {
                paramTypes.push_back(getTypeFromToken(gen, param.type));
            }
        }
        
        // 2. Funktions-Typ erstellen
        Type* retType = getTypeFromToken(gen, returnType);
        FunctionType* funcType = FunctionType::get(retType, paramTypes, false);
        
        // 3. Funktion erstellen
        Function* func = Function::Create(
            funcType, 
            Function::ExternalLinkage, 
            name, 
            gen.module.get()
        );
        
        // 4. Entry-Block erstellen
        BasicBlock* entry = BasicBlock::Create(gen.context, "entry", func);
        gen.builder.SetInsertPoint(entry);
        
        // 5. Parameter in lokale Variablen kopieren
        unsigned idx = 0;
        for (auto& param : parameters) {
            Argument* arg = func->getArg(idx++);
            arg->setName(param.name);
            
            Type* paramType = getTypeFromToken(gen, param.type);
            AllocaInst* alloca = gen.createFunctionBlockAlloca(param.name, paramType, func);
            gen.builder.CreateStore(arg, alloca);
            gen.namedValues[param.name] = alloca;
        }
        
        // 6. Body generieren
        for (auto& stmt : body) {
            stmt->codegen(gen);
        }
        
        // 7. Falls kein explizites return: return 0 oder void
        if (returnType == INT) {
            gen.builder.CreateRet(gen.builder.getInt32(0));
        } else {
            gen.builder.CreateRetVoid();
        }
        
        return func;
    }
    
private:
    Type* getTypeFromToken(LLVMCodeGen& gen, TokenType type) {
        switch(type) {
            case INT: return gen.builder.getInt32Ty();
            case FLOAT: return gen.builder.getFloatTy();
            case STRING: return gen.builder.getInt8PtrTy();
            case BOOLEAN: return gen.builder.getInt1Ty();
            default: return gen.builder.getInt32Ty();
        }
    }
};

// Return-Statement
struct ReturnStatement : Statement {
    std::unique_ptr<Expr> returnExpr;
    
    ReturnStatement(Expr* e) : returnExpr(e) {}
    
    void codegen(LLVMCodeGen& gen) override {
        if (returnExpr) {
            Value* retVal = returnExpr->codegen(gen);
            gen.builder.CreateRet(retVal);
        } else {
            gen.builder.CreateRetVoid();
        }
    }
};

// Funktionsaufruf
struct CallExpr : Expr {
    std::string functionName;
    std::vector<std::unique_ptr<Expr>> arguments;
    
    CallExpr(const std::string& name) 
        : Expr(ExprKind::Call), functionName(name) {}
    
    Value* codegen(LLVMCodeGen& gen) override {
        // Funktion finden
        Function* func = gen.module->getFunction(functionName);
        if (!func) {
            std::cerr << "Unknown function: " << functionName << "\n";
            return nullptr;
        }
        
        // Argumente generieren
        std::vector<Value*> args;
        for (auto& arg : arguments) {
            args.push_back(arg->codegen(gen));
        }
        
        // Funktionsaufruf
        return gen.builder.CreateCall(func, args, "calltmp");
    }
};

struct AssignmentStatement : Statement {
    std::string objectName;
    std::string memberName;
    std::unique_ptr<Expr> valueExpr;
    
    AssignmentStatement(const std::string& obj, const std::string& mem, Expr* expr)
        : objectName(obj), memberName(mem), valueExpr(expr) {}
    
    void codegen(LLVMCodeGen& gen) override {
        if (!valueExpr) return;
        
        AllocaInst* structPtr = gen.namedValues[objectName];
        if (!structPtr) return;
        
        Type* structPtrType = structPtr->getAllocatedType();
        if (!structPtrType->isStructTy()) return;
        
        std::string structTypeName = objectName + "_t";
        if (gen.structFieldIndices.find(structTypeName) == gen.structFieldIndices.end()) {
            return;
        }
        
        unsigned fieldIdx = gen.structFieldIndices[structTypeName][memberName];
        
        Value* zero = gen.builder.getInt32(0);
        Value* idx = gen.builder.getInt32(fieldIdx);
        Value* fieldPtr = gen.builder.CreateInBoundsGEP(structPtrType, structPtr, {zero, idx}, memberName);
        
        Value* value = valueExpr->codegen(gen);
        if (value) {
            gen.builder.CreateStore(value, fieldPtr);
        }
    }
};

struct PrintStatement : Statement {
    std::unique_ptr<Expr> expr;
    
    PrintStatement(Expr* e) : expr(e) {}
    
    void codegen(LLVMCodeGen& gen) override {
        if (!expr) return;
        
        Value* val = expr->codegen(gen);
        if (!val) return;
        
        Value* formatStr = nullptr;
        std::vector<Value*> args;
        
        Type* valType = val->getType();
        
        if (valType->isIntegerTy(32)) {
            formatStr = gen.createGlobalString("%d\n");
            args.push_back(formatStr);
            args.push_back(val);
        } else if (valType->isIntegerTy(64)) {
            formatStr = gen.createGlobalString("%ld\n");
            args.push_back(formatStr);
            args.push_back(val);
        } else if (valType->isIntegerTy(1)) {
            Value* extended = gen.builder.CreateZExt(val, gen.builder.getInt32Ty(), "boolext");
            formatStr = gen.createGlobalString("%d\n");
            args.push_back(formatStr);
            args.push_back(extended);
        } else if (valType->isFloatTy()) {
            Value* promoted = gen.builder.CreateFPExt(val, gen.builder.getDoubleTy(), "promoted");
            formatStr = gen.createGlobalString("%f\n");
            args.push_back(formatStr);
            args.push_back(promoted);
        } else if (valType->isDoubleTy()) {
            formatStr = gen.createGlobalString("%f\n");
            args.push_back(formatStr);
            args.push_back(val);
        } else if (valType->isPointerTy()) {
            formatStr = gen.createGlobalString("%s\n");
            args.push_back(formatStr);
            args.push_back(val);
        } else {
            formatStr = gen.createGlobalString("<unknown type>\n");
            args.push_back(formatStr);
        }
        
        gen.builder.CreateCall(gen.printfFunc, args);
    }
};

struct ScanStatement : Statement {
    std::string variableName;
    
    ScanStatement(const std::string& varName) : variableName(varName) {}
    
    void codegen(LLVMCodeGen& gen) override {
        AllocaInst* varAlloca = gen.namedValues[variableName];
        if (!varAlloca) return;
        
        Value* promptStr = gen.createGlobalString("> ");
        std::vector<Value*> printArgs;
        printArgs.push_back(promptStr);
        gen.builder.CreateCall(gen.printfFunc, printArgs);
        
        Value* formatStr = gen.createGlobalString("%d");
        std::vector<Value*> scanArgs;
        scanArgs.push_back(formatStr);
        scanArgs.push_back(varAlloca);
        gen.builder.CreateCall(gen.scanfFunc, scanArgs);
    }
};

struct ExitStatement : Statement {
    std::unique_ptr<Expr> codeExpr;
    
    ExitStatement(Expr* e) : codeExpr(e) {}
    
    void codegen(LLVMCodeGen& gen) override {
        Value* exitCode = codeExpr ? codeExpr->codegen(gen) : gen.builder.getInt32(0);
        if (!exitCode) return;
        
        std::vector<Value*> args;
        args.push_back(exitCode);
        gen.builder.CreateCall(gen.exitFunc, args);
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

        if (c == '0' && pos + 1 < input.size() && input[pos + 1] == 'x') {
            pos += 2;
            size_t start = pos;
            while (pos < input.size() && isxdigit(input[pos])) pos++;
            return {HEX_NUMBER, input.substr(start - 2, pos - start + 2)};
        }

        if (c == '"') {
            pos++;
            size_t start = pos;
            while (pos < input.size() && input[pos] != '"') pos++;
            std::string str = input.substr(start, pos - start);
            if (pos < input.size()) pos++;
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
            else if (word == "if") return {IF, word};
            else if (word == "while") return {WHILE, word};
            else if (word == "times") return {TIMES, word};
            else if (word == "return") return {RETURN, word};
            else return {IDENT, word};
        }

        if (isdigit(c)) {
            size_t start = pos;
            while (pos < input.size() && isdigit(input[pos])) pos++;
            return {NUMBER, input.substr(start, pos - start)};
        }

        pos++;
        switch(c) {
            case '\\': return {BACKSLASH, "\\"};
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
            case '$': return {DOLLAR, "$"};
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

    void nextToken() { currentToken = lexer.getNextToken(); }
    
    void skipComplexTypeAnnotations() {
        while (currentToken.type == STAR || 
               currentToken.type == BACKSLASH ||
               currentToken.type == OPEN_BRACKET || 
               currentToken.type == CLOSE_BRACKET ||
               currentToken.type == LOWER ||
               currentToken.type == HIGHER ||
               currentToken.type == OPEN_PAREN ||
               currentToken.type == CLOSE_PAREN ||
               currentToken.type == COMMA) {
            nextToken();
            if (currentToken.type == IDENT || currentToken.type == NUMBER) nextToken();
        }
    }

    // Parse Funktion: $int max(int a, int b) { ... }
    FunctionDecl* parseFunction() {
        if (currentToken.type != DOLLAR) return nullptr;
        nextToken();
        
        // Return-Typ
        TokenType returnType = currentToken.type;
        nextToken();
        
        // Funktionsname
        if (currentToken.type != IDENT) return nullptr;
        std::string name = currentToken.text;
        nextToken();
        
        // Parameter: (int a, int b)
        if (currentToken.type != OPEN_PAREN) return nullptr;
        nextToken();
        
        std::vector<Parameter> parameters;
        while (currentToken.type != CLOSE_PAREN) {
            // Parameter-Typ
            TokenType paramType = currentToken.type;
            nextToken();
            
            // Varargs?
            bool isVarArgs = false;
            if (currentToken.type == DOT) {
                nextToken();
                if (currentToken.type == DOT) {
                    nextToken();
                    if (currentToken.type == DOT) {
                        nextToken();
                        isVarArgs = true;
                    }
                }
            }
            
            // Parameter-Name
            if (currentToken.type != IDENT) break;
            std::string paramName = currentToken.text;
            nextToken();
            
            parameters.push_back({paramType, paramName, isVarArgs});
            
            // Komma?
            if (currentToken.type == COMMA) {
                nextToken();
            }
        }
        
        if (currentToken.type == CLOSE_PAREN) nextToken();
        
        // Body: { ... }
        if (currentToken.type != OPEN_BRACE) return nullptr;
        nextToken();
        
        std::vector<std::unique_ptr<Statement>> body;
        while (currentToken.type != CLOSE_BRACE && currentToken.type != END) {
            Statement* stmt = parseStatement();
            if (stmt) {
                body.push_back(std::unique_ptr<Statement>(stmt));
            }
        }
        
        if (currentToken.type == CLOSE_BRACE) nextToken();
        
        auto* func = new FunctionDecl();
        func->returnType = returnType;
        func->name = name;
        func->parameters = std::move(parameters);
        func->body = std::move(body);
        return func;
    }
    
    // Parse Funktionsaufruf: max(5, 10)
    Expr* parseFunctionCall(const std::string& name) {
        auto* call = new CallExpr(name);
        
        // (
        if (currentToken.type != OPEN_PAREN) return nullptr;
        nextToken();
        
        // Argumente
        while (currentToken.type != CLOSE_PAREN && currentToken.type != END) {
            Expr* arg = parseExpr();
            if (arg) {
                call->arguments.push_back(std::unique_ptr<Expr>(arg));
            }
            
            if (currentToken.type == COMMA) {
                nextToken();
            }
        }
        
        if (currentToken.type == CLOSE_PAREN) nextToken();
        
        return call;
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
            
            // Funktionsaufruf?
            if (currentToken.type == OPEN_PAREN) {
                return parseFunctionCall(name);
            }
            
            // Member-Access?
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
            if (currentToken.type == CLOSE_PAREN) nextToken();
            return expr;
        }
        
        return nullptr;
    }
    
    // Parse return: x#return oder curVal#return
    Statement* parseReturnStatement(const std::string& varName) {
        if (currentToken.type == HASH) {
            nextToken();
            if (currentToken.type == IDENT && currentToken.text == "return") {
                nextToken();
                if (currentToken.type == SEMICOLON) nextToken();
                return new ReturnStatement(new IdentExpr(varName));
            }
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
        
        auto* obj = new ObjectLiteralExpr();
        
        while (currentToken.type != CLOSE_BRACE && currentToken.type != END) {
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
                nextToken();
            }
        }
        
        if (currentToken.type == CLOSE_BRACE) {
            nextToken();
        }
        
        return obj;
    }

    Statement* parseDeclaration() {
        TokenType type = currentToken.type;
        nextToken();
        
        // Skip complex type annotations (*, [], <>, etc.)
        skipComplexTypeAnnotations();

        if (currentToken.type != IDENT) return nullptr;
        std::string name = currentToken.text;
        nextToken();

        Expr* initExpr = nullptr;
        if (currentToken.type == EQUAL) {
            nextToken();
            
            // For OBJECT: Check if { comes
            if (type == OBJECT && currentToken.type == OPEN_BRACE) {
                initExpr = parseObjectLiteral();
            } else if (type == HASHMAP && currentToken.type == OPEN_BRACE) {
                // Skip hashmap initialization for now
                int braceDepth = 1;
                nextToken();
                while (braceDepth > 0 && currentToken.type != END) {
                    if (currentToken.type == OPEN_BRACE) braceDepth++;
                    if (currentToken.type == CLOSE_BRACE) braceDepth--;
                    if (braceDepth > 0) nextToken();
                }
                if (currentToken.type == CLOSE_BRACE) nextToken();
                initExpr = nullptr;
            } else {
                initExpr = parseExpr();
            }
        }

        if (currentToken.type == SEMICOLON) nextToken();
        return new Declaration(type, name, initExpr);
    }

    Statement* parseAssignment() {
        std::string objName = currentToken.text;
        nextToken();
        
        if (currentToken.type == HASH) {
            nextToken();
            if (currentToken.type == IDENT && currentToken.text == "scan") {
                nextToken();
                if (currentToken.type == SEMICOLON) nextToken();
                return new ScanStatement(objName);
            }
            if ((currentToken.type == IDENT && currentToken.text == "print") || currentToken.type == PRINT) {
                nextToken();
                if (currentToken.type == SEMICOLON) nextToken();
                return new PrintStatement(new IdentExpr(objName));
            }
            if (currentToken.type == RETURN || (currentToken.type == IDENT && currentToken.text == "return")) {
            nextToken();
            if (currentToken.type == SEMICOLON) nextToken();
            return new ReturnStatement(new IdentExpr(objName));
            }
            if (currentToken.type == IDENT && currentToken.text == "stopWithExitCode") {
                nextToken();
                if (currentToken.type == SEMICOLON) nextToken();
                return new ExitStatement(new IdentExpr(objName));
            }
        }
        
        if (currentToken.type == DOT) {
            nextToken();
            if (currentToken.type != IDENT) return nullptr;
            
            std::string memberName = currentToken.text;
            nextToken();
            
            if (currentToken.type == HASH) {
                nextToken();
                if ((currentToken.type == IDENT && currentToken.text == "print") || currentToken.type == PRINT) {
                    nextToken();
                    if (currentToken.type == SEMICOLON) nextToken();
                    
                    if (memberName == "to_s") {
                        return new PrintStatement(new IdentExpr(objName));
                    }
                    
                    return new PrintStatement(new MemberAccessExpr(objName, memberName));
                }
            }
            
            if (currentToken.type == EQUAL) {
                nextToken();
                Expr* valueExpr = parseExpr();
                if (currentToken.type == SEMICOLON) nextToken();
                return new AssignmentStatement(objName, memberName, valueExpr);
            }
        }
        
        return nullptr;
    }

    Statement* parseStatement() {
        if (currentToken.type == PRINT) {
            nextToken();
            Expr* expr = parseExpr();
            if (currentToken.type == SEMICOLON) nextToken();
            return new PrintStatement(expr);
        }

        if (currentToken.type == INT || currentToken.type == BOOLEAN 
            || currentToken.type == STRING || currentToken.type == FLOAT
            || currentToken.type == DOUBLE || currentToken.type == LONG
            || currentToken.type == HASHMAP || currentToken.type == OBJECT) {
            return parseDeclaration();
        }

        if (currentToken.type == IDENT || currentToken.type == NUMBER) {
            return parseAssignment();
        }

        return nullptr;
    }

public:
    std::vector<std::unique_ptr<FunctionDecl>> functions;

    Parser(Lexer& lex) : lexer(lex) { nextToken(); }

    std::vector<std::unique_ptr<Statement>> parseProgram() {
        std::vector<std::unique_ptr<Statement>> stmts;
        
        while (currentToken.type != END) {
            // Funktion?
            if (currentToken.type == DOLLAR) {
                FunctionDecl* func = parseFunction();
                if (func) {
                    functions.push_back(std::unique_ptr<FunctionDecl>(func));
                    continue;
                }
            }
            
            // Normale Statements
            Statement* stmt = parseStatement();
            if (stmt) {
                stmts.push_back(std::unique_ptr<Statement>(stmt));
            } else {
                nextToken();
            }
        }
        
        return stmts;
    }
};

int main(int argc, char* argv[]) {
    std::cout << "HopperLang LLVM Compiler gestartet\n";
    
    std::string inputPath = "main.hpl";
    std::string outputPath = "output.o";
    
    if (argc > 1) inputPath = argv[1];
    if (argc > 2) outputPath = argv[2];
    
    std::ifstream file(inputPath.c_str());
    if (!file) {
        std::cerr << "Fehler: Datei " + inputPath + " nicht gefunden.\n";
        return 1;
    }

    std::string code((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());

    Lexer lexer(code);
    Parser parser(lexer);
    
    std::vector<std::unique_ptr<Statement> > statements = parser.parseProgram();
    auto functions = parser.functions;
    
    std::cout << "Generiere LLVM IR...\n";
    
    LLVMCodeGen gen("HopperLang");

    gen.generateFunctions(functions);
    
    for (size_t i = 0; i < statements.size(); i++) {
        statements[i]->codegen(gen);
    }
    
    gen.finish();
    
    if (!gen.verify()) {
        std::cerr << "Modul-Verifikation fehlgeschlagen!\n";
        return 1;
    }
    
    std::cout << "\n=== LLVM IR ===\n";
    gen.print();
    std::cout << "\n";
    
    std::cout << "Generiere Object-Datei...\n";
    if (!gen.emitObjectFile(outputPath)) {
        std::cerr << "Fehler beim Erzeugen der Object-Datei!\n";
        return 1;
    }
    
    std::cout << "Object-Datei wurde nach " << outputPath << " geschrieben\n";
    std::cout << "\nLinke mit:\n";
    std::cout << "  clang " << outputPath << " -o program\n";
    std::cout << "  ./program\n";
    
    return 0;
}
