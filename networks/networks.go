package networks

import (
	. "github.com/AccumulateNetwork/accumulated/config"
)

type Network struct {
	Name  string
	Type  NetworkType
	Port  int
	Nodes []Node
}

type Node struct {
	IP   string
	Type NodeType
}

var Networks = map[string]*Network{
	"BVC0": {
		Name: "BVC0",
		Type: BVC,
		Port: 33000,
		Nodes: []Node{
			{"3.140.120.192", Validator},
			{"18.220.147.250", Validator},
		},
	},
	"BVC1": {
		Name: "BVC1",
		Type: BVC,
		Port: 33000,
		Nodes: []Node{
			{"65.0.156.146", Validator},
			{"13.234.254.178", Validator},
		},
	},
	"BVC2": {
		Name: "BVC2",
		Type: BVC,
		Port: 33000,
		Nodes: []Node{
			{"13.48.159.117", Validator},
			{"16.170.126.251", Validator},
		},
	},
	"Arches": {
		Name: "Arches",
		Type: BVC,
		Port: 33000,
		Nodes: []Node{
			{"13.51.10.110", Validator},
			{"13.232.230.216", Validator},
		},
	},
	"AmericanSamoa": {
		Name: "AmericanSamoa",
		Type: BVC,
		Port: 33000,
		Nodes: []Node{
			{"18.221.39.36", Validator},
			{"44.236.45.58", Validator},
		},
	},
	"Badlands": {
		Name: "Badlands",
		Type: BVC,
		Port: 35550,
		Nodes: []Node{
			{"127.0.0.1", Validator},
		},
	},
	"EastXeons": {
		Name: "EastXeons",
		Type: BVC,
		Port: 33000,
		Nodes: []Node{
			{"18.119.26.7", Validator},
			{"18.119.149.208", Validator},
		},
	},
	"EastXeons-DC": {
		Name: "EastXeons-DC",
		Type: DC,
		Port: 33100,
		Nodes: []Node{
			{"18.119.26.7", Validator},
			{"18.119.149.208", Validator},
		},
	},
	"Localhost": {
		Name: "Localhost",
		Type: BVC,
		Port: 26656,
		Nodes: []Node{
			{"127.0.1.1", Validator},
			{"127.0.1.2", Validator},
			{"127.0.1.3", Validator},
		},
	},
}
