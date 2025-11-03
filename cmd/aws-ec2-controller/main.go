package main

import (
	"fyne.io/fyne/v2/app"
	"github.com/littl3-kitty/Aws_EC2_Controller/internal/ui"
)

func main() {
	a := app.New()
	w := ui.NewMainWindow(a)
	w.ShowAndRun()
}
