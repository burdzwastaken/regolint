package model

// CodeContext is the root structure passed to Rego policies for evaluation.
type CodeContext struct {
	FilePath    string            `json:"file_path"`
	ModulePath  string            `json:"module_path"`
	Package     PackageInfo       `json:"package"`
	Imports     []ImportInfo      `json:"imports"`
	Functions   []FunctionInfo    `json:"functions"`
	Types       []TypeInfo        `json:"types"`
	Variables   []VariableInfo    `json:"variables"`
	Constants   []VariableInfo    `json:"constants"`
	Calls       []CallInfo        `json:"calls"`
	TypeUsages  []TypeUsageInfo   `json:"type_usages"`
	FieldAccess []FieldAccessInfo `json:"field_accesses"`
}

// Position represents a location in source code.
type Position struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// PackageInfo contains package-level metadata.
type PackageInfo struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Doc  string `json:"doc,omitempty"`
}

// ImportInfo represents an import declaration.
type ImportInfo struct {
	Path     string   `json:"path"`
	Alias    string   `json:"alias,omitempty"`
	Position Position `json:"position"`
}

// ParameterInfo represents a function parameter or return value.
type ParameterInfo struct {
	Name string `json:"name,omitempty"`
	Type string `json:"type"`
}

// FunctionInfo represents a function or method declaration.
type FunctionInfo struct {
	Name        string          `json:"name"`
	Receiver    string          `json:"receiver,omitempty"`
	Parameters  []ParameterInfo `json:"parameters"`
	Returns     []ParameterInfo `json:"returns"`
	IsExported  bool            `json:"is_exported"`
	IsTest      bool            `json:"is_test"`
	Complexity  int             `json:"complexity"`
	LineCount   int             `json:"line_count"`
	Position    Position        `json:"position"`
	Comments    []string        `json:"comments,omitempty"`
	Annotations map[string]any  `json:"annotations,omitempty"`
}

// FieldInfo represents a struct field.
type FieldInfo struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Tags       string   `json:"tags,omitempty"`
	IsExported bool     `json:"is_exported"`
	IsEmbedded bool     `json:"is_embedded"`
	Position   Position `json:"position"`
}

// MethodInfo represents a method signature in an interface or struct.
type MethodInfo struct {
	Name       string          `json:"name"`
	Parameters []ParameterInfo `json:"parameters"`
	Returns    []ParameterInfo `json:"returns"`
	IsExported bool            `json:"is_exported"`
}

// TypeInfo represents a type declaration.
type TypeInfo struct {
	Name       string       `json:"name"`
	Kind       string       `json:"kind"`
	IsExported bool         `json:"is_exported"`
	Fields     []FieldInfo  `json:"fields,omitempty"`
	Methods    []MethodInfo `json:"methods,omitempty"`
	Embeds     []string     `json:"embeds,omitempty"`
	Implements []string     `json:"implements,omitempty"`
	Position   Position     `json:"position"`
	Doc        string       `json:"doc,omitempty"`
}

// VariableInfo represents a variable or constant declaration.
type VariableInfo struct {
	Name       string   `json:"name"`
	Type       string   `json:"type,omitempty"`
	IsExported bool     `json:"is_exported"`
	IsConst    bool     `json:"is_const"`
	Value      string   `json:"value,omitempty"`
	InFunction string   `json:"in_function,omitempty"`
	Position   Position `json:"position"`
}

// CallInfo represents a function or method call.
type CallInfo struct {
	Function     string   `json:"function"`
	Package      string   `json:"package,omitempty"`
	Receiver     string   `json:"receiver,omitempty"`
	ReceiverType string   `json:"receiver_type,omitempty"`
	Args         []string `json:"args,omitempty"`
	InFunction   string   `json:"in_function"`
	Position     Position `json:"position"`
}

// TypeUsageInfo represents a reference to a type.
type TypeUsageInfo struct {
	TypeName   string   `json:"type_name"`
	Package    string   `json:"package,omitempty"`
	InFunction string   `json:"in_function,omitempty"`
	Context    string   `json:"context"`
	Position   Position `json:"position"`
}

// FieldAccessInfo represents a field access expression.
type FieldAccessInfo struct {
	Field      string   `json:"field"`
	Receiver   string   `json:"receiver"`
	Type       string   `json:"type,omitempty"`
	InFunction string   `json:"in_function"`
	Position   Position `json:"position"`
}

// Violation represents a policy violation returned by Rego evaluation.
type Violation struct {
	Message  string   `json:"message"`
	Rule     string   `json:"rule"`
	Severity string   `json:"severity,omitempty"`
	Position Position `json:"position"`
	Fix      *Fix     `json:"fix,omitempty"`
}

// Fix represents an auto-fix suggestion for a violation.
type Fix struct {
	Description string    `json:"description"`
	Edits       []FixEdit `json:"edits,omitempty"`
}

// FixEdit represents a single text edit to fix a violation.
type FixEdit struct {
	Position Position `json:"position"`
	OldText  string   `json:"old_text,omitempty"`
	NewText  string   `json:"new_text"`
}

// PackageContext aggregates CodeContext from all files in a package.
type PackageContext struct {
	ModulePath   string         `json:"module_path"`
	Package      PackageInfo    `json:"package"`
	Files        []CodeContext  `json:"files"`
	AllImports   []ImportInfo   `json:"all_imports"`
	AllFunctions []FunctionInfo `json:"all_functions"`
	AllTypes     []TypeInfo     `json:"all_types"`
	AllVariables []VariableInfo `json:"all_variables"`
	AllConstants []VariableInfo `json:"all_constants"`
	AllCalls     []CallInfo     `json:"all_calls"`
}
