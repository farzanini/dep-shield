//go:build wails

// dep-shield GUI — Wails v2 entry point.
//
// Build with:
//
//	wails build
//
// Develop with live reload:
//
//	wails dev
//
// The CLI entry point lives in main.go (built without the wails tag):
//
//	go build -o dep-shield-cli .
package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	err := wails.Run(&options.App{
		Title:  "dep-shield",
		Width:  1400,
		Height: 900,
		MinWidth:  900,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		// Dark gray background matches the Tailwind gray-900 body colour so
		// there is no flash of white before the React app mounts.
		BackgroundColour: &options.RGBA{R: 17, G: 24, B: 39, A: 255},
		OnStartup:        app.startup,
		OnShutdown:       app.shutdown,
		Bind:             []interface{}{app},
		// EnableDefaultContextMenu is false (default) — right-click menus are
		// implemented in React for results rows.
		EnableDefaultContextMenu: false,
	})
	if err != nil {
		log.Fatalf("wails: %v", err)
	}
}
