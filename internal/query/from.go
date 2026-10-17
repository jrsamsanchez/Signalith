package query

import "strings"

// from is Splunk's | from, read as the search it stands for:
// | from datamodel:Authentication is datamodel=Authentication, and
// | from lookup:owners is | inputlookup owners. The events keep their
// fields' own names.
type from struct {
	q    Query     // a data model's search
	cmds []Command // or the command it stands for
}

func (*from) Name() string { return "from" }

const fromExample = "| from datamodel:Authentication"

// fromConstraints are CIM datasets below a data model's root node, as
// the search that keeps only their events.
var fromConstraints = map[string]string{
	"Authentication.Failed_Authentication":     "action=failure",
	"Authentication.Successful_Authentication": "action=success",
}

func (p *parser) parseFrom(cmd token) (Command, error) {
	t := p.next()
	if t.kind != tokWord {
		return nil, errorf(cmd.pos, "from reads datamodel:<name> or lookup:<table>, for example: %s", fromExample)
	}
	kind, name, ok := strings.Cut(t.text, ":")
	if !ok {
		// from datamodel Authentication
		kind = t.text
		if strings.EqualFold(kind, "datamodel") || strings.EqualFold(kind, "lookup") || strings.EqualFold(kind, "inputlookup") {
			n := p.peek()
			if n.kind != tokWord && n.kind != tokString {
				return nil, errorf(n.pos, "from %s needs a name, for example: %s", kind, fromExample)
			}
			name = p.next().text
		}
	} else if name == "" {
		n := p.peek()
		if (n.kind != tokWord && n.kind != tokString) || n.pos != t.pos+len(t.text) {
			return nil, errorf(t.pos, "from %s needs a name, for example: %s", t.text, fromExample)
		}
		name = p.next().text
	}
	f := &from{}
	switch strings.ToLower(kind) {
	case "datamodel":
		model, _, _, ok := tstatsTarget(name)
		constraint, child := fromConstraints[name]
		if child {
			model, ok = "Authentication", true
		}
		if !ok {
			return nil, errorf(t.pos, "from cannot read data model %q; use one such as Authentication, Authentication.Failed_Authentication, Endpoint.Processes, Network_Traffic or Web", name)
		}
		f.q.Datamodel = model
		if child {
			sq, err := Parse(constraint)
			if err != nil {
				return nil, err
			}
			f.q.Search = sq.Search
		}
	case "lookup", "inputlookup":
		if !lookupTableRE.MatchString(strings.TrimSuffix(name, ".csv")) {
			return nil, errorf(t.pos, "%q is not a lookup table name; names use lower-case letters, digits, - and _", name)
		}
		f.cmds = []Command{&InputLookup{Table: strings.TrimSuffix(name, ".csv")}}
	default:
		return nil, errorf(t.pos, "from reads datamodel:<name> or lookup:<table> in Signalith, for example: %s", fromExample)
	}
	return f, p.endCommand()
}
