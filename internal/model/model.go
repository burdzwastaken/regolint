package model

// CodeContext is the root structure passed to Rego policies for evaluation.
type CodeContext struct {
	FilePath          string                 `json:"file_path"`
	ModulePath        string                 `json:"module_path"`
	Package           PackageInfo            `json:"package"`
	Imports           []ImportInfo           `json:"imports"`
	Functions         []FunctionInfo         `json:"functions"`
	Types             []TypeInfo             `json:"types"`
	Variables         []VariableInfo         `json:"variables"`
	Constants         []VariableInfo         `json:"constants"`
	Lines             []LineInfo             `json:"lines,omitempty"`
	Comments          []CommentInfo          `json:"comments,omitempty"`
	Literals          []LiteralInfo          `json:"literals,omitempty"`
	CompositeLiterals []CompositeLiteralInfo `json:"composite_literals,omitempty"`
	Returns           []ReturnInfo           `json:"returns,omitempty"`
	Ifs               []IfInfo               `json:"ifs,omitempty"`
	TypeAssertions    []TypeAssertInfo       `json:"type_assertions,omitempty"`
	MakeSlices        []MakeSliceInfo        `json:"make_slices,omitempty"`
	Appends           []AppendInfo           `json:"appends,omitempty"`
	ResourceAcquires  []ResourceInfo         `json:"resource_acquires,omitempty"`
	ResourceCloses    []ResourceClose        `json:"resource_closes,omitempty"`
	ResourceErrs      []ResourceErr          `json:"resource_errs,omitempty"`
	Subtests          []SubtestInfo          `json:"subtests,omitempty"`
	RangeLoops        []RangeLoopInfo        `json:"range_loops,omitempty"`
	LoopVarCopies     []LoopVarCopyInfo      `json:"loop_var_copies,omitempty"`
	BlankAssignments  []BlankAssignInfo      `json:"blank_assignments,omitempty"`
	DeclGroups        []DeclGroupInfo        `json:"decl_groups,omitempty"`
	Declarations      []DeclInfo             `json:"declarations,omitempty"`
	Calls             []CallInfo             `json:"calls"`
	TypeUsages        []TypeUsageInfo        `json:"type_usages"`
	FieldAccess       []FieldAccessInfo      `json:"field_accesses"`
	Nolints           []NolintDirective      `json:"nolints,omitempty"`
}

// DeclInfo represents a top-level declaration in source order.
type DeclInfo struct {
	Kind     string   `json:"kind"`
	Name     string   `json:"name"`
	Position Position `json:"position"`
}

// DeclGroupInfo represents a top-level declaration group.
type DeclGroupInfo struct {
	Kind      string   `json:"kind"`
	Count     int      `json:"count"`
	IsGrouped bool     `json:"is_grouped"`
	BlockID   int      `json:"block_id"`
	Position  Position `json:"position"`
}

// LineInfo represents a source line.
type LineInfo struct {
	Number   int      `json:"number"`
	Length   int      `json:"length"`
	Position Position `json:"position"`
}

// BlankAssignInfo represents an assignment with blank identifiers.
type BlankAssignInfo struct {
	BlankCount int      `json:"blank_count"`
	TotalCount int      `json:"total_count"`
	InFunction string   `json:"in_function,omitempty"`
	Position   Position `json:"position"`
}

// LiteralInfo represents a literal expression.
type LiteralInfo struct {
	Kind       string   `json:"kind"`
	Value      string   `json:"value"`
	InFunction string   `json:"in_function,omitempty"`
	Position   Position `json:"position"`
}

// CompositeLiteralInfo represents a composite literal expression.
type CompositeLiteralInfo struct {
	Type         string   `json:"type"`
	TypeIdentity string   `json:"type_identity,omitempty"`
	TypeKind     string   `json:"type_kind,omitempty"`
	Fields       []string `json:"fields,omitempty"`
	InFunction   string   `json:"in_function,omitempty"`
	Position     Position `json:"position"`
}

// ReturnInfo represents a return statement.
type ReturnInfo struct {
	Function string   `json:"function"`
	Receiver string   `json:"receiver,omitempty"`
	Results  []string `json:"results,omitempty"`
	IsNaked  bool     `json:"is_naked"`
	Position Position `json:"position"`
}

// IfInfo represents an if statement and its direct return statements.
type IfInfo struct {
	Function    string       `json:"function"`
	Receiver    string       `json:"receiver,omitempty"`
	Condition   string       `json:"condition"`
	ErrorVar    string       `json:"error_var,omitempty"`
	IsErrNotNil bool         `json:"is_err_not_nil"`
	Returns     []ReturnInfo `json:"returns,omitempty"`
	Position    Position     `json:"position"`
}

// TypeAssertInfo represents a type assertion expression.
type TypeAssertInfo struct {
	Expr          string   `json:"expr"`
	AssertedType  string   `json:"asserted_type"`
	InFunction    string   `json:"in_function,omitempty"`
	Context       string   `json:"context"`
	IsCommaOK     bool     `json:"is_comma_ok"`
	AssignmentTok string   `json:"assignment_tok,omitempty"`
	ValueTarget   string   `json:"value_target,omitempty"`
	OKTarget      string   `json:"ok_target,omitempty"`
	Position      Position `json:"position"`
}

// MakeSliceInfo represents a make([]T, len[, cap]) expression assigned to a target.
type MakeSliceInfo struct {
	Target     string   `json:"target"`
	LenArg     string   `json:"len_arg"`
	CapArg     string   `json:"cap_arg,omitempty"`
	HasCap     bool     `json:"has_cap"`
	InFunction string   `json:"in_function,omitempty"`
	Position   Position `json:"position"`
}

// AppendInfo represents an append call and its assignment target.
type AppendInfo struct {
	Target     string   `json:"target,omitempty"`
	Source     string   `json:"source"`
	InFunction string   `json:"in_function,omitempty"`
	Position   Position `json:"position"`
}

// ResourceInfo represents an acquired resource that usually needs cleanup/checking.
type ResourceInfo struct {
	Kind       string   `json:"kind"`
	Target     string   `json:"target"`
	Source     string   `json:"source"`
	InFunction string   `json:"in_function,omitempty"`
	Position   Position `json:"position"`
}

// ResourceClose represents a Close call on a resource.
type ResourceClose struct {
	Target     string   `json:"target"`
	IsDefer    bool     `json:"is_defer"`
	InFunction string   `json:"in_function,omitempty"`
	Position   Position `json:"position"`
}

// ResourceErr represents an Err call on a resource.
type ResourceErr struct {
	Target     string   `json:"target"`
	IsChecked  bool     `json:"is_checked"`
	InFunction string   `json:"in_function,omitempty"`
	Position   Position `json:"position"`
}

// RangeLoopInfo represents a for-range loop.
type RangeLoopInfo struct {
	Key        string   `json:"key,omitempty"`
	Value      string   `json:"value,omitempty"`
	Source     string   `json:"source"`
	InFunction string   `json:"in_function,omitempty"`
	EndLine    int      `json:"end_line,omitempty"`
	Position   Position `json:"position"`
}

// LoopVarCopyInfo represents a redundant copy of a range loop variable.
type LoopVarCopyInfo struct {
	Variable   string   `json:"variable"`
	Kind       string   `json:"kind"`
	InFunction string   `json:"in_function,omitempty"`
	Position   Position `json:"position"`
}

// CommentInfo represents a source comment.
type CommentInfo struct {
	Text        string   `json:"text"`
	Raw         string   `json:"raw,omitempty"`
	IsFirstLine bool     `json:"is_first_line"`
	Position    Position `json:"position"`
}

// NolintDirective represents a nolint comment that suppresses violations.
type NolintDirective struct {
	Line    int      `json:"line"`
	EndLine int      `json:"end_line,omitempty"`
	Rules   []string `json:"rules,omitempty"`
	Reason  string   `json:"reason,omitempty"`
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
	Name         string `json:"name,omitempty"`
	Type         string `json:"type"`
	TypeIdentity string `json:"type_identity,omitempty"`
	IsVariadic   bool   `json:"is_variadic,omitempty"`
}

// FunctionInfo represents a function or method declaration.
type FunctionInfo struct {
	Name        string          `json:"name"`
	Receiver    string          `json:"receiver,omitempty"`
	Parameters  []ParameterInfo `json:"parameters"`
	Returns     []ParameterInfo `json:"returns"`
	IsExported  bool            `json:"is_exported"`
	IsTest      bool            `json:"is_test"`
	HasNakedRet bool            `json:"has_naked_ret"`
	Complexity  int             `json:"complexity"`
	MaxIfDepth  int             `json:"max_if_depth"`
	LineCount   int             `json:"line_count"`
	Position    Position        `json:"position"`
	Comments    []string        `json:"comments,omitempty"`
	Annotations map[string]any  `json:"annotations,omitempty"`
}

// FieldInfo represents a struct field.
type FieldInfo struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	TypeIdentity string   `json:"type_identity,omitempty"`
	Tags         string   `json:"tags,omitempty"`
	IsExported   bool     `json:"is_exported"`
	IsEmbedded   bool     `json:"is_embedded"`
	Position     Position `json:"position"`
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
	BlockID    int      `json:"block_id,omitempty"`
	UsesIota   bool     `json:"uses_iota,omitempty"`
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
	InFuncLit    bool     `json:"in_func_lit,omitempty"`
	Position     Position `json:"position"`
}

// SubtestInfo represents a t.Run subtest callback.
type SubtestInfo struct {
	Name        string   `json:"name,omitempty"`
	Function    string   `json:"function"`
	TestParam   string   `json:"test_param,omitempty"`
	HasParallel bool     `json:"has_parallel"`
	Position    Position `json:"position"`
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
	ModulePath           string                 `json:"module_path"`
	Package              PackageInfo            `json:"package"`
	Files                []CodeContext          `json:"files"`
	AllImports           []ImportInfo           `json:"all_imports"`
	AllFunctions         []FunctionInfo         `json:"all_functions"`
	AllTypes             []TypeInfo             `json:"all_types"`
	AllVariables         []VariableInfo         `json:"all_variables"`
	AllConstants         []VariableInfo         `json:"all_constants"`
	AllLines             []LineInfo             `json:"all_lines"`
	AllComments          []CommentInfo          `json:"all_comments"`
	AllLiterals          []LiteralInfo          `json:"all_literals"`
	AllCompositeLiterals []CompositeLiteralInfo `json:"all_composite_literals"`
	AllReturns           []ReturnInfo           `json:"all_returns"`
	AllIfs               []IfInfo               `json:"all_ifs"`
	AllTypeAssertions    []TypeAssertInfo       `json:"all_type_assertions"`
	AllMakeSlices        []MakeSliceInfo        `json:"all_make_slices"`
	AllAppends           []AppendInfo           `json:"all_appends"`
	AllResourceAcquires  []ResourceInfo         `json:"all_resource_acquires"`
	AllResourceCloses    []ResourceClose        `json:"all_resource_closes"`
	AllResourceErrs      []ResourceErr          `json:"all_resource_errs"`
	AllSubtests          []SubtestInfo          `json:"all_subtests"`
	AllRangeLoops        []RangeLoopInfo        `json:"all_range_loops"`
	AllLoopVarCopies     []LoopVarCopyInfo      `json:"all_loop_var_copies"`
	AllBlankAssignments  []BlankAssignInfo      `json:"all_blank_assignments"`
	AllDeclGroups        []DeclGroupInfo        `json:"all_decl_groups"`
	AllDeclarations      []DeclInfo             `json:"all_declarations"`
	AllCalls             []CallInfo             `json:"all_calls"`
	AllTypeUsages        []TypeUsageInfo        `json:"all_type_usages"`
	AllFieldAccesses     []FieldAccessInfo      `json:"all_field_accesses"`
}
