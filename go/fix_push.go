package main

import (
	"os"
	"strings"
)

func main() {
	path := "/var/home/nrd/git/github.com/Cyphrme/Cyphr/go/cyphr/commit.go"
	b, _ := os.ReadFile(path)
	content := string(b)

	oldStr := `func (p *PendingCommit) Push(cz *ParsedCoz) {
	if cz.Arrow != nil || cz.Kind == TxCommitCreate {
		p.commitTx = append(p.commitTx, cz)
	} else {
		p.transactions = append(p.transactions, cz)
	}
}`
	newStr := `func (p *PendingCommit) Push(cz *ParsedCoz) {
	if cz.Kind == TxCommitCreate {
		p.commitTx = append(p.commitTx, cz)
	} else {
		p.transactions = append(p.transactions, cz)
	}
}`

	content = strings.Replace(content, oldStr, newStr, 1)
	os.WriteFile(path, []byte(content), 0644)
}
