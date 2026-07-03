package plugin

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

type Plugin interface {
	Name() string
	Version() string
	Description() string
	Execute(ctx context.Context, target string, opts map[string]any) (Result, error)
	Validate(target string) bool
}

type Result struct {
	PluginName string
	Data     []byte
	Output   string
	Error    error
}

type Registry struct {
	plugins map[string]Plugin
}

func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
	}
}

func (r *Registry) Register(p Plugin) error {
	name := p.Name()
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %q already registered", name)
	}
	r.plugins[name] = p
	return nil
}

func (r *Registry) Unregister(name string) {
	delete(r.plugins, name)
}

func (r *Registry) Get(name string) (Plugin, bool) {
	p, ok := r.plugins[name]
	return p, ok
}

func (r *Registry) List() []string {
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (r *Registry) ExecuteAll(ctx context.Context, target string, opts map[string]any) []Result {
	var results []Result
	for _, p := range r.plugins {
		if ctx.Err() != nil {
			break
		}
		if p.Validate(target) {
			result, err := p.Execute(ctx, target, opts)
			if err != nil {
				result.Error = err
			}
			results = append(results, result)
		}
	}
	return results
}

type BasePlugin struct {
	Name        string
	Version     string
	Description string
	RunFunc     func(ctx context.Context, target string, opts map[string]any) (string, error)
}

func (b *BasePlugin) Execute(ctx context.Context, target string, opts map[string]any) (Result, error) {
	output, err := b.RunFunc(ctx, target, opts)
	return Result{
		PluginName: b.Name,
		Output:   output,
		Error:    err,
	}, err
}

func (b *BasePlugin) Validate(target string) bool {
	return true
}

type PluginManager struct {
	registry     *Registry
	pluginsDir   string
}

func NewPluginManager(pluginsDir string) *PluginManager {
	return &PluginManager{
		registry:   NewRegistry(),
		pluginsDir: pluginsDir,
	}
}

func (pm *PluginManager) Registry() *Registry {
	return pm.registry
}

func (pm *PluginManager) Info() string {
	var b strings.Builder
	b.WriteString("Plugin Manager\n")
	b.WriteString("==============\n")
	b.WriteString(fmt.Sprintf("Plugins directory: %s\n", pm.pluginsDir))
	b.WriteString(fmt.Sprintf("Registered plugins: %d\n\n", len(pm.registry.List())))
	b.WriteString("Installed plugins:\n")

	plugins := pm.registry.List()
	if len(plugins) == 0 {
		b.WriteString("  (none)\n")
	} else {
		for _, name := range plugins {
			p, _ := pm.registry.Get(name)
			b.WriteString(fmt.Sprintf("  - %s v%s: %s\n", name, p.Version(), p.Description()))
		}
	}

	return b.String()
}
