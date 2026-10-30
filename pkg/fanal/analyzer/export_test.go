package analyzer

// PostAnalyzerTypes returns the types of the group's post-analyzers in the
// order PostAnalyze runs them.
func (ag AnalyzerGroup) PostAnalyzerTypes() []Type {
	types := make([]Type, len(ag.postAnalyzers))
	for i, a := range ag.postAnalyzers {
		types[i] = a.Type()
	}
	return types
}
