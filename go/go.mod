module github.com/cyphrme/cyphr

go 1.25.0

toolchain go1.25.9

require github.com/cyphrme/coz v1.0.0

require github.com/pelletier/go-toml/v2 v2.2.4

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/cyphrme/malt v0.0.0
	golang.org/x/crypto v0.46.0 // indirect
	golang.org/x/exp v0.0.0-20220722155223-a9213eeb770e // indirect
	golang.org/x/sys v0.39.0 // indirect
)

replace github.com/cyphrme/malt => ./malt
