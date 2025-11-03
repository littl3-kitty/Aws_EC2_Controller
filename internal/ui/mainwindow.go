package ui

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/littl3-kitty/Aws_EC2_Controller/internal/core"
)

type MainWindow struct {
	app    fyne.App
	window fyne.Window

	// 핵심 객체
	ec2Manager    *core.EC2Manager
	configManager *core.ConfigManager

	// UI 컴포넌트
	keyInput    *widget.Entry
	secretInput *widget.Entry
	loginBtn    *widget.Button

	regionFilter *widget.Select
	instanceList *widget.Table

	refreshBtn     *widget.Button
	allRefreshBtn  *widget.Button
	startBtn       *widget.Button
	stopBtn        *widget.Button
	terminateBtn   *widget.Button
	controlButtons []*widget.Button

	statusLabel *widget.Label

	// 데이터
	instances []core.Instance
	filtered  []core.Instance
	selected  map[int]bool
	mu        sync.RWMutex

	// 자동 새로고침
	autoRefreshTimer  *time.Timer
	autoRefreshCount  int
	autoRefreshActive bool
}

const (
	autoRefreshInterval = 3 * time.Second
	autoRefreshMaxCount = 30
)

var transitioningStates = map[string]bool{
	"pending":       true,
	"stopping":      true,
	"shutting-down": true,
	"terminating":   true,
}

func NewMainWindow(app fyne.App) *MainWindow {
	w := &MainWindow{
		app:           app,
		configManager: core.NewConfigManager(),
		selected:      make(map[int]bool),
	}

	w.window = app.NewWindow("EC2 Controller - v1.0.0")
	w.window.Resize(fyne.NewSize(1200, 600))
	w.window.SetContent(w.buildUI())
	w.window.CenterOnScreen()

	w.loadSavedCredentials()

	return w
}

func (w *MainWindow) ShowAndRun() {
	w.window.ShowAndRun()
}

func (w *MainWindow) buildUI() fyne.CanvasObject {
	return container.NewBorder(
		w.buildLoginSection(),
		w.buildBottomSection(),
		nil,
		nil,
		w.buildInstanceListSection(),
	)
}

func (w *MainWindow) buildLoginSection() fyne.CanvasObject {
	w.keyInput = widget.NewEntry()
	w.keyInput.SetPlaceHolder("Enter AWS Access Key")

	w.secretInput = widget.NewPasswordEntry()
	w.secretInput.SetPlaceHolder("Enter AWS Secret Key")

	w.loginBtn = widget.NewButton("Login", w.onLogin)

	form := container.New(layout.NewFormLayout(),
		widget.NewLabel("Access Key:"), w.keyInput,
		widget.NewLabel("Secret Key:"), w.secretInput,
		layout.NewSpacer(), w.loginBtn,
	)

	return container.NewVBox(
		form,
		widget.NewSeparator(),
	)
}

func (w *MainWindow) buildInstanceListSection() fyne.CanvasObject {
	// 리전 필터
	w.regionFilter = widget.NewSelect([]string{"ALL"}, func(selected string) {
		// nil 체크 추가
		if w.instanceList != nil {
			w.onRegionFilterChanged(selected)
		}
	})
	w.regionFilter.SetSelected("ALL")

	filterBar := container.NewBorder(
		nil, nil,
		widget.NewLabel("Region:"),
		nil,
		w.regionFilter,
	)

	// 인스턴스 테이블
	w.instanceList = widget.NewTable(
		func() (int, int) {
			w.mu.RLock()
			defer w.mu.RUnlock()
			return len(w.filtered) + 1, 8 // +1 for header
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(id widget.TableCellID, cell fyne.CanvasObject) {
			label := cell.(*widget.Label)

			if id.Row == 0 {
				// 헤더
				headers := []string{"Select", "Term Lock", "Stop Lock", "Instance ID", "Name", "Status", "Type", "Region"}
				label.SetText(headers[id.Col])
				label.TextStyle.Bold = true
				return
			}

			w.mu.RLock()
			defer w.mu.RUnlock()

			if id.Row-1 >= len(w.filtered) {
				return
			}

			inst := w.filtered[id.Row-1]

			switch id.Col {
			case 0: // Select
				if w.selected[id.Row-1] {
					label.SetText("☑")
				} else {
					label.SetText("☐")
				}
			case 1: // Termination Protection
				if inst.TerminationProtection {
					label.SetText("☑")
				} else {
					label.SetText("☐")
				}
			case 2: // Stop Protection
				if inst.StopProtection {
					label.SetText("☑")
				} else {
					label.SetText("☐")
				}
			case 3:
				label.SetText(inst.ID)
			case 4:
				label.SetText(inst.Name)
			case 5:
				label.SetText(inst.Status)
			case 6:
				label.SetText(inst.InstanceType)
			case 7:
				label.SetText(core.GetRegionDisplayName(inst.Region))
			}
		},
	)

	// 테이블 클릭 핸들러
	w.instanceList.OnSelected = w.onTableCellSelected

	// 컬럼 너비 설정
	w.instanceList.SetColumnWidth(0, 60)  // Select
	w.instanceList.SetColumnWidth(1, 100) // Term Lock
	w.instanceList.SetColumnWidth(2, 100) // Stop Lock
	w.instanceList.SetColumnWidth(3, 170) // Instance ID
	w.instanceList.SetColumnWidth(4, 140) // Name
	w.instanceList.SetColumnWidth(5, 100) // Status
	w.instanceList.SetColumnWidth(6, 120) // Type
	w.instanceList.SetColumnWidth(7, 250) // Region

	return container.NewBorder(
		filterBar,
		nil,
		nil,
		nil,
		container.NewScroll(w.instanceList),
	)
}

func (w *MainWindow) buildBottomSection() fyne.CanvasObject {
	w.refreshBtn = widget.NewButton("Refresh", w.onRefresh)
	w.allRefreshBtn = widget.NewButton("All Refresh", w.onAllRefresh)
	w.startBtn = widget.NewButton("Start", w.onStart)
	w.stopBtn = widget.NewButton("Stop", w.onStop)
	w.terminateBtn = widget.NewButton("Terminate", w.onTerminate)

	w.controlButtons = []*widget.Button{
		w.refreshBtn, w.allRefreshBtn, w.startBtn, w.stopBtn, w.terminateBtn,
	}

	// 초기 비활성화
	for _, btn := range w.controlButtons {
		btn.Disable()
	}

	w.statusLabel = widget.NewLabel("Login required (Click checkbox to select)")

	buttons := container.NewHBox(
		w.refreshBtn,
		w.allRefreshBtn,
		layout.NewSpacer(),
		w.startBtn,
		w.stopBtn,
		w.terminateBtn,
	)

	return container.NewVBox(
		widget.NewSeparator(),
		buttons,
		w.statusLabel,
	)
}

func (w *MainWindow) loadSavedCredentials() {
	if !w.configManager.HasSavedCredentials() {
		return
	}

	accessKey, secretKey, err := w.configManager.LoadCredentials()
	if err != nil {
		return
	}

	w.keyInput.SetText(accessKey)
	w.secretInput.SetText(secretKey)
}

func (w *MainWindow) onLogin() {
	accessKey := strings.TrimSpace(w.keyInput.Text)
	secretKey := strings.TrimSpace(w.secretInput.Text)

	if accessKey == "" || secretKey == "" {
		dialog.ShowError(fmt.Errorf("please enter both Access Key and Secret Key"), w.window)
		return
	}

	w.updateStatus("Logging in...")
	w.loginBtn.Disable()

	go func() {
		ec2Manager := core.NewEC2Manager(accessKey, secretKey)

		// 연결 테스트
		_, err := ec2Manager.GetAvailableRegions()
		if err != nil {
			w.loginBtn.Enable()
			dialog.ShowError(fmt.Errorf("login failed: %v", err), w.window)
			w.updateStatus("Login failed")
			return
		}

		// 성공
		w.ec2Manager = ec2Manager
		w.configManager.SaveCredentials(accessKey, secretKey)

		// UI 업데이트
		w.keyInput.Disable()
		w.secretInput.Disable()

		for _, btn := range w.controlButtons {
			btn.Enable()
		}

		w.updateStatus("Login successful. Loading instances...")
		w.onAllRefresh()
	}()
}

func (w *MainWindow) onRefresh() {
	selected := w.regionFilter.Selected

	if selected == "ALL" {
		// 현재 로드된 모든 리전 새로고침
		w.mu.RLock()
		regions := make(map[string]bool)
		for _, inst := range w.instances {
			regions[inst.Region] = true
		}
		w.mu.RUnlock()

		if len(regions) == 0 {
			return
		}

		for region := range regions {
			w.refreshRegion(region, false)
		}
	} else {
		// 선택된 리전만
		region := w.extractRegionCode(selected)
		w.refreshRegion(region, false)
	}
}

func (w *MainWindow) onAllRefresh() {
	w.updateStatus("Loading instances from all regions...")

	go func() {
		instances, err := w.ec2Manager.GetAllInstances()
		if err != nil {
			dialog.ShowError(fmt.Errorf("failed to load instances: %v", err), w.window)
			return
		}

		w.mu.Lock()
		w.instances = instances
		w.mu.Unlock()

		// 리전 필터 업데이트
		w.updateRegionFilter()
		w.filterInstances()

		w.updateStatus(fmt.Sprintf("%d instances loaded", len(instances)))
		w.checkAutoRefresh()
	}()
}

func (w *MainWindow) refreshRegion(region string, silent bool) {
	if !silent {
		w.updateStatus(fmt.Sprintf("Refreshing %s...", region))
	}

	go func() {
		instances, err := w.ec2Manager.GetInstancesInRegion(region)
		if err != nil {
			if !silent {
				dialog.ShowError(fmt.Errorf("failed to refresh %s: %v", region, err), w.window)
			}
			return
		}

		w.mu.Lock()
		// 해당 리전의 기존 인스턴스 제거
		filtered := []core.Instance{}
		for _, inst := range w.instances {
			if inst.Region != region {
				filtered = append(filtered, inst)
			}
		}
		filtered = append(filtered, instances...)
		w.instances = filtered
		w.mu.Unlock()

		w.filterInstances()

		if !silent {
			w.updateStatus(fmt.Sprintf("%d instances refreshed", len(instances)))
		}
		w.checkAutoRefresh()
	}()
}

func (w *MainWindow) onStart() {
	selected := w.getSelectedInstances()
	if len(selected) == 0 {
		dialog.ShowInformation("Warning", "Please select instances", w.window)
		return
	}

	w.updateStatus(fmt.Sprintf("Starting %d instance(s)...", len(selected)))

	go func() {
		grouped := w.groupByRegion(selected)

		for region, ids := range grouped {
			err := w.ec2Manager.StartInstances(ids, region)
			if err != nil {
				dialog.ShowError(fmt.Errorf("failed to start instances: %v", err), w.window)
				return
			}
		}

		dialog.ShowInformation("Success", fmt.Sprintf("%d instance(s) started", len(selected)), w.window)
		w.onRefresh()
	}()
}

func (w *MainWindow) onStop() {
	selected := w.getSelectedInstances()
	if len(selected) == 0 {
		dialog.ShowInformation("Warning", "Please select instances", w.window)
		return
	}

	// Stop protection 체크
	w.mu.RLock()
	var protected []string
	for _, inst := range selected {
		if inst.StopProtection {
			name := inst.Name
			if name == "" {
				name = inst.ID
			}
			protected = append(protected, name)
		}
	}
	w.mu.RUnlock()

	if len(protected) > 0 {
		msg := "Cannot stop protected instances:\n\n" + strings.Join(protected[:min(5, len(protected))], "\n")
		if len(protected) > 5 {
			msg += fmt.Sprintf("\n... and %d more", len(protected)-5)
		}
		msg += "\n\nDisable stop protection first."
		dialog.ShowError(fmt.Errorf(msg), w.window)
		return
	}

	w.updateStatus(fmt.Sprintf("Stopping %d instance(s)...", len(selected)))

	go func() {
		grouped := w.groupByRegion(selected)

		for region, ids := range grouped {
			err := w.ec2Manager.StopInstances(ids, region)
			if err != nil {
				dialog.ShowError(fmt.Errorf("failed to stop instances: %v", err), w.window)
				return
			}
		}

		dialog.ShowInformation("Success", fmt.Sprintf("%d instance(s) stopped", len(selected)), w.window)
		w.onRefresh()
	}()
}

func (w *MainWindow) onTerminate() {
	selected := w.getSelectedInstances()
	if len(selected) == 0 {
		dialog.ShowInformation("Warning", "Please select instances", w.window)
		return
	}

	// Termination protection 체크
	w.mu.RLock()
	var protected []string
	for _, inst := range selected {
		if inst.TerminationProtection {
			name := inst.Name
			if name == "" {
				name = inst.ID
			}
			protected = append(protected, name)
		}
	}
	w.mu.RUnlock()

	if len(protected) > 0 {
		msg := "Cannot terminate protected instances:\n\n" + strings.Join(protected[:min(5, len(protected))], "\n")
		if len(protected) > 5 {
			msg += fmt.Sprintf("\n... and %d more", len(protected)-5)
		}
		msg += "\n\nDisable termination protection first."
		dialog.ShowError(fmt.Errorf(msg), w.window)
		return
	}

	// 확인 다이얼로그
	confirmMsg := fmt.Sprintf("Are you sure you want to TERMINATE %d instance(s)?\n\n"+
		"This action CANNOT be undone!\n"+
		"All data on the instance will be permanently deleted.", len(selected))

	dialog.ShowConfirm("Confirm Termination", confirmMsg, func(ok bool) {
		if !ok {
			return
		}

		w.updateStatus(fmt.Sprintf("Terminating %d instance(s)...", len(selected)))

		go func() {
			grouped := w.groupByRegion(selected)

			for region, ids := range grouped {
				err := w.ec2Manager.TerminateInstances(ids, region)
				if err != nil {
					dialog.ShowError(fmt.Errorf("failed to terminate instances: %v", err), w.window)
					return
				}
			}

			dialog.ShowInformation("Success", fmt.Sprintf("%d instance(s) terminated", len(selected)), w.window)
			w.onRefresh()
		}()
	}, w.window)
}

func (w *MainWindow) onTableCellSelected(id widget.TableCellID) {
	if id.Row == 0 {
		return // 헤더 클릭 무시
	}

	row := id.Row - 1

	w.mu.RLock()
	if row >= len(w.filtered) {
		w.mu.RUnlock()
		return
	}
	inst := w.filtered[row]
	w.mu.RUnlock()

	switch id.Col {
	case 0: // Select 체크박스
		w.mu.Lock()
		w.selected[row] = !w.selected[row]
		w.mu.Unlock()
		w.instanceList.Refresh()

	case 1: // Termination Protection
		go w.toggleProtection(inst.ID, inst.Region, "termination", !inst.TerminationProtection)

	case 2: // Stop Protection
		go w.toggleProtection(inst.ID, inst.Region, "stop", !inst.StopProtection)
	}
}

func (w *MainWindow) toggleProtection(instanceID, region, protectionType string, enabled bool) {
	var err error
	var protectionName string

	if protectionType == "termination" {
		err = w.ec2Manager.SetTerminationProtection(instanceID, region, enabled)
		protectionName = "Termination Protection"
	} else {
		err = w.ec2Manager.SetStopProtection(instanceID, region, enabled)
		protectionName = "Stop Protection"
	}

	if err != nil {
		dialog.ShowError(fmt.Errorf("failed to toggle protection: %v", err), w.window)
		return
	}

	action := "enabled"
	if !enabled {
		action = "disabled"
	}

	w.updateStatus(fmt.Sprintf("%s %s for %s", protectionName, action, instanceID))
	w.refreshRegion(region, true)
}

func (w *MainWindow) onRegionFilterChanged(selected string) {
	w.filterInstances()
}

func (w *MainWindow) filterInstances() {
	// nil 체크 추가
	if w.instanceList == nil {
		return
	}

	selected := w.regionFilter.Selected
	regionCode := w.extractRegionCode(selected)

	w.mu.Lock()
	defer w.mu.Unlock()

	w.filtered = []core.Instance{}
	w.selected = make(map[int]bool)

	for _, inst := range w.instances {
		if selected == "ALL" || inst.Region == regionCode {
			w.filtered = append(w.filtered, inst)
		}
	}

	// 정렬
	sort.Slice(w.filtered, func(i, j int) bool {
		if w.filtered[i].Name == "" && w.filtered[j].Name != "" {
			return false
		}
		if w.filtered[i].Name != "" && w.filtered[j].Name == "" {
			return true
		}
		if w.filtered[i].Name != w.filtered[j].Name {
			return w.filtered[i].Name < w.filtered[j].Name
		}
		return w.filtered[i].ID < w.filtered[j].ID
	})

	w.instanceList.Refresh()
}

func (w *MainWindow) updateRegionFilter() {
	w.mu.RLock()
	defer w.mu.RUnlock()

	regions := make(map[string]bool)
	for _, inst := range w.instances {
		regions[inst.Region] = true
	}

	regionList := []string{"ALL"}
	for region := range regions {
		regionList = append(regionList, core.GetRegionDisplayName(region))
	}

	sort.Strings(regionList[1:]) // ALL은 제외하고 정렬

	w.regionFilter.Options = regionList
	w.regionFilter.Refresh()
}

func (w *MainWindow) getSelectedInstances() []core.Instance {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var selected []core.Instance
	for idx, isSelected := range w.selected {
		if isSelected && idx < len(w.filtered) {
			selected = append(selected, w.filtered[idx])
		}
	}

	return selected
}

func (w *MainWindow) groupByRegion(instances []core.Instance) map[string][]string {
	grouped := make(map[string][]string)
	for _, inst := range instances {
		grouped[inst.Region] = append(grouped[inst.Region], inst.ID)
	}
	return grouped
}

func (w *MainWindow) checkAutoRefresh() {
	if w.autoRefreshTimer != nil {
		w.autoRefreshTimer.Stop()
		w.autoRefreshTimer = nil
	}

	w.mu.RLock()
	hasTransitioning := false
	for _, inst := range w.instances {
		if transitioningStates[inst.Status] {
			hasTransitioning = true
			break
		}
	}
	w.mu.RUnlock()

	if hasTransitioning && w.autoRefreshCount < autoRefreshMaxCount {
		w.autoRefreshCount++
		w.autoRefreshTimer = time.AfterFunc(autoRefreshInterval, func() {
			w.onRefresh()
		})
	} else {
		w.autoRefreshCount = 0
	}
}

func (w *MainWindow) updateStatus(text string) {
	w.statusLabel.SetText(text)
	w.statusLabel.Refresh()
}

func (w *MainWindow) extractRegionCode(display string) string {
	if strings.Contains(display, "(") {
		return strings.Split(display, " (")[0]
	}
	return display
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
