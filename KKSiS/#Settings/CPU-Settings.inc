
;---- Skin Toggle ----

[Background1]
Meter=Shape
Shape=Rectangle 10,35,100,95,3 | Fill Color 50,50,50

[Title1]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=40
Text=#VarToggle#

[Divider1]
Meter=Shape
Shape=Rectangle 12,55,96,2,0 | Fill Color 160,160,160

[Toggle1a]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnToggle.png
X=20
Y=65
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\CPU" "CPU.ini"]

[Toggle1aText]
Meter=String
MeterStyle=SettingsStyle-Text
X=30r
Y=5r
Text=Panel Skin

[Toggle1b]
Meter=Button
ButtonImage=#@#Images\Buttons\BtnToggle.png
X=-30r
Y=23r
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\CPU" "CPU.ini"]

[Toggle1bText]
Meter=String
MeterStyle=SettingsStyle-Text
X=30r
Y=5r
Text=Circle Skin


;---- Panel Skin Size ----

[Background2]
Meter=Shape
Shape=Rectangle 120,35,100,95,3 | Fill Color 50,50,50

[Title2]
Meter=String
MeterStyle=SettingsStyle-Text
X=125
Y=40
Text=#VarPanelSize#

[Divider2]
Meter=Shape
Shape=Rectangle 122,55,96,2,0 | Fill Color 160,160,160

[Button2a]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn80x14.png
X=130
Y=65
ButtonCommand=[!WriteKeyValue Variables "Panel-CPUSize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU"]
[Button2aText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarSmall#

[Button2b]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn80x14.png
X=130
Y=21r
ButtonCommand=[!WriteKeyValue Variables "Panel-CPUSize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU"]
[Button2bText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarSquare#

[Button2c]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn80x14.png
X=130
Y=21r
ButtonCommand=[!WriteKeyValue Variables "Panel-CPUSize" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU"]
[Button2cText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarBig#


;---- Options ----

[Background3]
Meter=Shape
Shape=Rectangle 230,35,160,95,3 | Fill Color 50,50,50

[Title3]
Meter=String
MeterStyle=SettingsStyle-Text
X=235
Y=40
Text=#VarOptions#

[Divider3]
Meter=Shape
Shape=Rectangle 232,55,156,2,0 | Fill Color 160,160,160

[ButtonDescription31]
Meter=String
MeterStyle=SettingsStyle-Text
Text=Graph / Bar
X=235
Y=65
[Button31a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#CPUHideGraph#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "CPUHideGraph" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#CPUHideGraph#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "CPUHideGraph" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh]

[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineName# Label
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#CPUHideRLLabel#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "CPUHideRLLabel" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#CPUHideRLLabel#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "CPUHideRLLabel" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#CPUColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "CPUColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#CPUColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "CPUColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh]


;-- Technology -------------------------------------------------------------------------------- 

[BG3]
Meter=Shape
Shape=Rectangle 10,140,380,65,3 | Fill Color 50,50,50

[T3Text]
Meter=String
MeterStyle=SettingsStyle-Text
Y=145
Text=#VarTechnology#

[T3Divider]
Meter=Shape
Shape=Rectangle 12,160,375,2,0 | Fill Color 160,160,160

[Technology1Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn100x25.png
X=20
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "CPUFormat" "Windows" "#@#Variables.inc"][!WriteKeyValue Variables "CPUFormat2" "" "#@#Variables.inc"][!WriteKeyValue Variables "CPUHideWindows" "0" "#@#Variables.inc"][!WriteKeyValue Variables "CPUHideHWiNFO" "1" "#@#Variables.inc"][!WriteKeyValue Variables "CPUHideMSIAB" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh]

[Technology1Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=50r
Y=6r
Text=Windows

[Technology2aBtn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn60x25.png
X=68r
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "CPUFormat" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "CPUFormat2" "" "#@#Variables.inc"][!WriteKeyValue Variables "CPUHideWindows" "1" "#@#Variables.inc"][!WriteKeyValue Variables "CPUHideHWiNFO" "0" "#@#Variables.inc"][!WriteKeyValue Variables "CPUHideMSIAB" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh]

[Technology2aText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=30r
Y=6r
Text=HWiNFO 1

[Technology2bBtn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn60x25.png
X=32r
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "CPUFormat" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "CPUFormat2" "2" "#@#Variables.inc"][!WriteKeyValue Variables "CPUHideWindows" "1" "#@#Variables.inc"][!WriteKeyValue Variables "CPUHideHWiNFO" "0" "#@#Variables.inc"][!WriteKeyValue Variables "CPUHideMSIAB" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh]

[Technology2bText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=30r
Y=6r
Text=HWiNFO 2

[Technology3Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn100x25.png
X=47r
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "CPUFormat" "MSIAB" "#@#Variables.inc"][!WriteKeyValue Variables "CPUFormat2" "" "#@#Variables.inc"][!WriteKeyValue Variables "CPUHideWindows" "1" "#@#Variables.inc"][!WriteKeyValue Variables "CPUHideHWiNFO" "1" "#@#Variables.inc"][!WriteKeyValue Variables "CPUHideMSIAB" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh]

[Technology3Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=50r
Y=6r
Text=MSI Afterburner


;-- Windows -------------------------------------------------------------------------------- 

[Windows-BG1]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50
Group=Windows
Hidden=#CPUHideWindows#

[Windows-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=Windows
Group=Windows
Hidden=#CPUHideWindows#

[Windows-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160
Group=Windows
Hidden=#CPUHideWindows#

[Windows-LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=240
Text=----- #VarLeftRL# ------#CRLF#Name: CPU Usage
Hidden=#CPUHideWindows#

[Windows-RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=380
Y=240
Text=------ #VarRightRL# ------#CRLF#Name: CPU Usage
Hidden=#CPUHideWindows#

[Windows_Image]
Meter=Image
ImageName=#@#Images\General\Windows-CPU.png
X=135
Y=265
W=125
Hidden=#CPUHideWindows#

;---- Title ----

[Windows-Input1-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=145
Y=386
Text=CPU Name:
Hidden=#CPUHideWindows#

[Windows-Input1-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=386
Text=(%1 = AutoDetect)
Hidden=#CPUHideWindows#

[Windows-Input1-BG]
Meter=Shape
Shape=Rectangle 150,385,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Windows-Input1-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideWindows#

[Windows-Input1-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=386
Text=#CPUNameWin#
Hidden=#CPUHideWindows#

[Windows-Input1-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=386
W=95
H=13
FocusDismiss=0
DefaultValue=#CPUNameWin#
Command1=[!SetVariable CPUNameWin "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUNameWin [Windows-Input1-Field] "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]


;-- HWiNFO -------------------------------------------------------------------------------- 

[HWiNFO-BG1]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50
Group=HWiNFO
Hidden=#CPUHideHWiNFO#

[HWiNFO-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=HWiNFO
Group=HWiNFO
Hidden=#CPUHideHWiNFO#

[HWiNFO_Status]
Measure=Plugin
Plugin=Process
ProcessName=HWiNFO64.exe
RegExpSubstitute=1
Substitute="-1":"not running","1":"running"
IfCondition=(HWiNFO_Status = 1)
IfTrueAction=[!SetOption HWiNFO_StatusText FontColor "0,255,0"]
IfFalseAction=[!SetOption HWiNFO_StatusText FontColor "255,0,0"]

[HWiNFO_StatusText]
Meter=String
MeterStyle=SettingsStyle-Text
MeasureName=HWiNFO_Status
StringAlign=Right
Y=220
X=380
Text=%1
Hidden=#CPUHideHWiNFO#

[HWiNFO-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160
Group=HWiNFO
Hidden=#CPUHideHWiNFO#

[HWiNFO_Measure_LeftRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-LeftRL_Id#
HWiNFOSensorInstance=#CPU-LeftRL_Instance#
HWiNFOEntryId		=#CPU-LeftRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1
Hidden=#CPUHideHWiNFO#


[HWiNFO_Measure_RightRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#CPU-RightRL_Id#
HWiNFOSensorInstance=#CPU-RightRL_Instance#
HWiNFOEntryId		=#CPU-RightRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1
Hidden=#CPUHideHWiNFO#

[HWiNFO_Image]
Meter=Image
ImageName=#@#Images\General\HWiNFO-CPU.png
X=135
Y=265
W=125
Hidden=#CPUHideHWiNFO#


;---- Left Roundline ----

[LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
MeasureName=HWiNFO_Measure_LeftRL_Name
X=15
Y=240
Text=----- #VarLeftRL# ------#CRLF#Name: %1
Hidden=#CPUHideHWiNFO#

[Input1a-BG]
Meter=Shape
Shape=Rectangle 15,280,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1a-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideHWiNFO#
[Input1b-BG]
Meter=Shape
Shape=Rectangle 15,300,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1b-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideHWiNFO#
[Input1c-BG]
Meter=Shape
Shape=Rectangle 15,320,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1c-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideHWiNFO#
[Input1d-BG]
Meter=Shape
Shape=Rectangle 15,340,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1d-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideHWiNFO#
[Input1e-BG]
Meter=Shape
Shape=Rectangle 15,360,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1e-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideHWiNFO#
[Input1a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=281
Text=SensorID: #CPU-LeftRL_Id#
Hidden=#CPUHideHWiNFO#
[Input1b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=301
Text=Instance: #CPU-LeftRL_Instance#
Hidden=#CPUHideHWiNFO#
[Input1c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=321
Text=EntryID: #CPU-LeftRL_EntryID#
Hidden=#CPUHideHWiNFO#
[Input1d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=341
Text=Max: #CPU_RLLeft_MaxValue#
Hidden=#CPUHideHWiNFO#
[Input1e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=361
Text=Min: #CPU_RLLeft_MinValue#
Hidden=#CPUHideHWiNFO#

[Input1a-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=281
W=115
H=13
FocusDismiss=0
DefaultValue=#CPU-LeftRL_Id#
Command1=[!SetVariable CPU-LeftRL_Id "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-LeftRL_Id [Input1a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input1b-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=301
W=105
H=13
FocusDismiss=0
DefaultValue=#CPU-LeftRL_Instance#
Command1=[!SetVariable CPU-LeftRL_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-LeftRL_Instance [Input1b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input1c-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=321
W=105
H=13
FocusDismiss=0
DefaultValue=#CPU-LeftRL_EntryID#
Command1=[!SetVariable CPU-LeftRL_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-LeftRL_EntryID [Input1c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input1d-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=341
W=95
H=13
FocusDismiss=0
DefaultValue=#CPU_RLLeft_MaxValue#
Command1=[!SetVariable CPU_RLLeft_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU_RLLeft_MaxValue [Input1d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]

[Input1e-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=361
W=95
H=13
FocusDismiss=0
DefaultValue=#CPU_RLLeft_MinValue#
Command1=[!SetVariable CPU_RLLeft_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU_RLLeft_MinValue [Input1e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]


;---- Right Roundline ----

[RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=380
Y=240
Text=------ #VarRightRL# ------#CRLF#Name: %1
Hidden=#CPUHideHWiNFO#

[Input2a-BG]
Meter=Shape
Shape=Rectangle 260,280,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2a-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideHWiNFO#
[Input2b-BG]
Meter=Shape
Shape=Rectangle 270,300,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2b-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideHWiNFO#
[Input2c-BG]
Meter=Shape
Shape=Rectangle 270,320,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2c-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideHWiNFO#
[Input2d-BG]
Meter=Shape
Shape=Rectangle 280,340,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2d-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideHWiNFO#
[Input2e-BG]
Meter=Shape
Shape=Rectangle 280,360,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2e-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideHWiNFO#
[Input2a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=281
Text=SensorID: #CPU-RightRL_Id#
Hidden=#CPUHideHWiNFO#
[Input2b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=301
Text=Instance: #CPU-RightRL_Instance#
Hidden=#CPUHideHWiNFO#
[Input2c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=321
Text=EntryID: #CPU-RightRL_EntryID#
Hidden=#CPUHideHWiNFO#
[Input2d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=341
Text=Max: #CPU_RLRight_MaxValue#
Hidden=#CPUHideHWiNFO#
[Input2e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=361
Text=Min: #CPU_RLRight_MinValue#
Hidden=#CPUHideHWiNFO#

[Input2a-Field]
Measure=Plugin
Plugin=InputText
X=261
Y=281
W=115
H=13
FocusDismiss=0
DefaultValue=#CPU-RightRL_Id#
Command1=[!SetVariable CPU-RightRL_Id "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-RightRL_Id [Input2a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input2b-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=301
W=105
H=13
FocusDismiss=0
DefaultValue=#CPU-RightRL_Instance#
Command1=[!SetVariable CPU-RightRL_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-RightRL_Instance [Input2b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input2c-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=321
W=105
H=13
FocusDismiss=0
DefaultValue=#CPU-RightRL_EntryID#
Command1=[!SetVariable CPU-RightRL_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-RightRL_EntryID [Input2c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input2d-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=341
W=95
H=13
FocusDismiss=0
DefaultValue=#CPU_RLRight_MaxValue#
Command1=[!SetVariable CPU_RLRight_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU_RLRight_MaxValue [Input2d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]

[Input2e-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=361
W=95
H=13
FocusDismiss=0
DefaultValue=#CPU_RLRight_MinValue#
Command1=[!SetVariable CPU_RLRight_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU_RLRight_MinValue [Input2e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]


;---- Title ----

[Input3-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=145
Y=386
Text=CPU Name:
Hidden=#CPUHideHWiNFO#

[Input3-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=386
Text=(%1 = AutoDetect)
Hidden=#CPUHideHWiNFO#

[Input3-BG]
Meter=Shape
Shape=Rectangle 150,385,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input3-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideHWiNFO#

[Input3-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=386
Text=#CPUName#
Hidden=#CPUHideHWiNFO#

[Input3-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=386
W=95
H=13
FocusDismiss=0
DefaultValue=#CPUName#
Command1=[!SetVariable CPUName "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUName [Input3-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]


;---- HWiNFO Sensors

[HWiNFO-Divider2]
Meter=Shape
Shape=Rectangle 12,410,375,2,0 | Fill Color 160,160,160
Group=HWiNFO
Hidden=#CPUHideHWiNFO#

[HWiNFO-Sensor-Headline]
Meter=String
MeterStyle=SettingsStyle-Text
Hidden=#CPUHideHWiNFO#
StringAlign=Right
X=360
Y=420
Text="Sensor ID        Instance         Entry ID"

;-- Configuration Input -------------------------------------------------------------------------------- 

[Input4-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=441
Text="Total CPU Usage"
Hidden=#CPUHideHWiNFO#

[Input4a-BG]
Meter=Shape
Shape=Rectangle 160,440,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4a-Field "ExecuteBatch 1-2"]
[Input4b-BG]
Meter=Shape
Shape=Rectangle 250,440,40,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4b-Field "ExecuteBatch 1-2"]
[Input4c-BG]
Meter=Shape
Shape=Rectangle 300,440,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4c-Field "ExecuteBatch 1-2"]

[Input4a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=441
Text=#CPU-Usage-Total_ID#
Hidden=#CPUHideHWiNFO#
[Input4b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU-Usage-Total_Instance#
Hidden=#CPUHideHWiNFO#
[Input4c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU-Usage-Total_EntryID#
Hidden=#CPUHideHWiNFO#

[Input4a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=441
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU-Usage-Total_ID#
Command1=[!SetVariable CPU-Usage-Total_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-Usage-Total_ID [Input4a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input4b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=441
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU-Usage-Total_Instance#
Command1=[!SetVariable CPU-Usage-Total_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-Usage-Total_Instance [Input4b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input4c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=441
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU-Usage-Total_EntryID#
Command1=[!SetVariable CPU-Usage-Total_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-Usage-Total_EntryID [Input4c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]


[Input5-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=461
Text="CPU Temperature"
Hidden=#CPUHideHWiNFO#

[Input5a-BG]
Meter=Shape
Shape=Rectangle 160,460,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5a-Field "ExecuteBatch 1-2"]
[Input5b-BG]
Meter=Shape
Shape=Rectangle 250,460,40,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5b-Field "ExecuteBatch 1-2"]
[Input5c-BG]
Meter=Shape
Shape=Rectangle 300,460,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5c-Field "ExecuteBatch 1-2"]

[Input5a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=461
Text=#CPU-Temp_ID#
Hidden=#CPUHideHWiNFO#
[Input5b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU-Temp_Instance#
Hidden=#CPUHideHWiNFO#
[Input5c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU-Temp_EntryID#
Hidden=#CPUHideHWiNFO#

[Input5a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=461
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU-Temp_ID#
Command1=[!SetVariable CPU-Temp_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-Temp_ID [Input5a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input5b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=461
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU-Temp_Instance#
Command1=[!SetVariable CPU-Temp_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-Temp_Instance [Input5b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input5c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=461
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU-Temp_EntryID#
Command1=[!SetVariable CPU-Temp_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-Temp_EntryID [Input5c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]


[Input6-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=481
Text="CPU FAN1"
Hidden=#CPUHideHWiNFO#

[Input6a-BG]
Meter=Shape
Shape=Rectangle 160,480,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6a-Field "ExecuteBatch 1-2"]
[Input6b-BG]
Meter=Shape
Shape=Rectangle 250,480,40,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6b-Field "ExecuteBatch 1-2"]
[Input6c-BG]
Meter=Shape
Shape=Rectangle 300,480,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6c-Field "ExecuteBatch 1-2"]

[Input6a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=481
Text=#CPU-FAN1_ID#
Hidden=#CPUHideHWiNFO#
[Input6b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU-FAN1_Instance#
Hidden=#CPUHideHWiNFO#
[Input6c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU-FAN1_EntryID#
Hidden=#CPUHideHWiNFO#

[Input6a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=481
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU-FAN1_ID#
Command1=[!SetVariable CPU-FAN1_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-FAN1_ID [Input6a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input6b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=481
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU-FAN1_Instance#
Command1=[!SetVariable CPU-FAN1_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-FAN1_Instance [Input6b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input6c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=481
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU-FAN1_EntryID#
Command1=[!SetVariable CPU-FAN1_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-FAN1_EntryID [Input6c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]


[Input7-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=501
Text="CPU FAN2"
Hidden=#CPUHideHWiNFO#

[Input7a-BG]
Meter=Shape
Shape=Rectangle 160,500,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7a-Field "ExecuteBatch 1-2"]
[Input7b-BG]
Meter=Shape
Shape=Rectangle 250,500,40,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7b-Field "ExecuteBatch 1-2"]
[Input7c-BG]
Meter=Shape
Shape=Rectangle 300,500,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7c-Field "ExecuteBatch 1-2"]

[Input7a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=501
Text=#CPU-FAN2_ID#
Hidden=#CPUHideHWiNFO#
[Input7b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU-FAN2_Instance#
Hidden=#CPUHideHWiNFO#
[Input7c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU-FAN2_EntryID#
Hidden=#CPUHideHWiNFO#

[Input7a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=501
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU-FAN2_ID#
Command1=[!SetVariable CPU-FAN2_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-FAN2_ID [Input7a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input7b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=501
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU-FAN2_Instance#
Command1=[!SetVariable CPU-FAN2_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-FAN2_Instance [Input7b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input7c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=501
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU-FAN2_EntryID#
Command1=[!SetVariable CPU-FAN2_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-FAN2_EntryID [Input7c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]


[Input8-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=521
Text="CPU VCore/VID"
Hidden=#CPUHideHWiNFO#

[Input8a-BG]
Meter=Shape
Shape=Rectangle 160,520,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input8a-Field "ExecuteBatch 1-2"]
[Input8b-BG]
Meter=Shape
Shape=Rectangle 250,520,40,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input8b-Field "ExecuteBatch 1-2"]
[Input8c-BG]
Meter=Shape
Shape=Rectangle 300,520,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input8c-Field "ExecuteBatch 1-2"]

[Input8a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=521
Text=#CPU-VCore_ID#
Hidden=#CPUHideHWiNFO#
[Input8b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU-VCore_Instance#
Hidden=#CPUHideHWiNFO#
[Input8c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU-VCore_EntryID#
Hidden=#CPUHideHWiNFO#

[Input8a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=521
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU-VCore_ID#
Command1=[!SetVariable CPU-VCore_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-VCore_ID [Input8a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input8b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=521
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU-VCore_Instance#
Command1=[!SetVariable CPU-VCore_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-VCore_Instance [Input8b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input8c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=521
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU-VCore_EntryID#
Command1=[!SetVariable CPU-VCore_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-VCore_EntryID [Input8c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]

[Input9-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=541
Text="CPU Package Power"
Hidden=#CPUHideHWiNFO#

[Input9a-BG]
Meter=Shape
Shape=Rectangle 160,540,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input9a-Field "ExecuteBatch 1-2"]
[Input9b-BG]
Meter=Shape
Shape=Rectangle 250,540,40,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input9b-Field "ExecuteBatch 1-2"]
[Input9c-BG]
Meter=Shape
Shape=Rectangle 300,540,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input9c-Field "ExecuteBatch 1-2"]

[Input9a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=541
Text=#CPU-PackagePwr_ID#
Hidden=#CPUHideHWiNFO#
[Input9b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPU-PackagePwr_Instance#
Hidden=#CPUHideHWiNFO#
[Input9c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPU-PackagePwr_EntryID#
Hidden=#CPUHideHWiNFO#

[Input9a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=541
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU-PackagePwr_ID#
Command1=[!SetVariable CPU-PackagePwr_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-PackagePwr_ID [Input9a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input9b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=541
W=35
H=13
FocusDismiss=0
DefaultValue=#CPU-PackagePwr_Instance#
Command1=[!SetVariable CPU-PackagePwr_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-PackagePwr_Instance [Input9b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input9c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=541
W=75
H=13
FocusDismiss=0
DefaultValue=#CPU-PackagePwr_EntryID#
Command1=[!SetVariable CPU-PackagePwr_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU-PackagePwr_EntryID [Input9c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]


[Input10-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=561
Text="CPUBx Frequency/Clock"
Hidden=#CPUHideHWiNFO#

[Input10a-BG]
Meter=Shape
Shape=Rectangle 160,560,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input10a-Field "ExecuteBatch 1-2"]
[Input10b-BG]
Meter=Shape
Shape=Rectangle 250,560,40,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input10b-Field "ExecuteBatch 1-2"]
[Input10c-BG]
Meter=Shape
Shape=Rectangle 300,560,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input10c-Field "ExecuteBatch 1-2"]

[Input10a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=561
Text=#CPUA-Clock_ID#
Hidden=#CPUHideHWiNFO#
[Input10b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPUA-Clock_Instance#
Hidden=#CPUHideHWiNFO#
[Input10c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPUA-Clock_EntryID#
Hidden=#CPUHideHWiNFO#

[Input10a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=561
W=75
H=13
FocusDismiss=0
DefaultValue=#CPUA-Clock_ID#
Command1=[!SetVariable CPUA-Clock_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUA-Clock_ID [Input10a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input10b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=561
W=35
H=13
FocusDismiss=0
DefaultValue=#CPUA-Clock_Instance#
Command1=[!SetVariable CPUA-Clock_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUA-Clock_Instance [Input10b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input10c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=561
W=75
H=13
FocusDismiss=0
DefaultValue=#CPUA-Clock_EntryID#
Command1=[!SetVariable CPUA-Clock_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUA-Clock_EntryID [Input10c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]


[Input11-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=581
Text="CPUCx Frequency/Clock"
Hidden=#CPUHideHWiNFO#

[Input11a-BG]
Meter=Shape
Shape=Rectangle 160,580,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input11a-Field "ExecuteBatch 1-2"]
[Input11b-BG]
Meter=Shape
Shape=Rectangle 250,580,40,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input11b-Field "ExecuteBatch 1-2"]
[Input11c-BG]
Meter=Shape
Shape=Rectangle 300,580,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input11c-Field "ExecuteBatch 1-2"]

[Input11a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=581
Text=#CPUB-Clock_ID#
Hidden=#CPUHideHWiNFO#
[Input11b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPUB-Clock_Instance#
Hidden=#CPUHideHWiNFO#
[Input11c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPUB-Clock_EntryID#
Hidden=#CPUHideHWiNFO#

[Input11a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=581
W=75
H=13
FocusDismiss=0
DefaultValue=#CPUB-Clock_ID#
Command1=[!SetVariable CPUB-Clock_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUB-Clock_ID [Input11a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input11b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=581
W=35
H=13
FocusDismiss=0
DefaultValue=#CPUB-Clock_Instance#
Command1=[!SetVariable CPUB-Clock_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUB-Clock_Instance [Input11b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input11c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=581
W=75
H=13
FocusDismiss=0
DefaultValue=#CPUB-Clock_EntryID#
Command1=[!SetVariable CPUB-Clock_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUB-Clock_EntryID [Input11c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]


[Input12-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=601
Text="CPUDx Frequency/Clock"
Hidden=#CPUHideHWiNFO#

[Input12a-BG]
Meter=Shape
Shape=Rectangle 160,600,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input12a-Field "ExecuteBatch 1-2"]
[Input12b-BG]
Meter=Shape
Shape=Rectangle 250,600,40,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input12b-Field "ExecuteBatch 1-2"]
[Input12c-BG]
Meter=Shape
Shape=Rectangle 300,600,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input12c-Field "ExecuteBatch 1-2"]

[Input12a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=601
Text=#CPUC-Clock_ID#
Hidden=#CPUHideHWiNFO#
[Input12b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPUC-Clock_Instance#
Hidden=#CPUHideHWiNFO#
[Input12c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPUC-Clock_EntryID#
Hidden=#CPUHideHWiNFO#

[Input12a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=601
W=75
H=13
FocusDismiss=0
DefaultValue=#CPUC-Clock_ID#
Command1=[!SetVariable CPUC-Clock_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUC-Clock_ID [Input12a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input12b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=601
W=35
H=13
FocusDismiss=0
DefaultValue=#CPUC-Clock_Instance#
Command1=[!SetVariable CPUC-Clock_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUC-Clock_Instance [Input12b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input12c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=601
W=75
H=13
FocusDismiss=0
DefaultValue=#CPUC-Clock_EntryID#
Command1=[!SetVariable CPUC-Clock_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUC-Clock_EntryID [Input12c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]

[Input13-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=621
Text="CPU4x Frequency/Clock"
Hidden=#CPUHideHWiNFO#

[Input13a-BG]
Meter=Shape
Shape=Rectangle 160,620,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input13a-Field "ExecuteBatch 1-2"]
[Input13b-BG]
Meter=Shape
Shape=Rectangle 250,620,40,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input13b-Field "ExecuteBatch 1-2"]
[Input13c-BG]
Meter=Shape
Shape=Rectangle 300,620,80,15,3 | Fill Color 0,0,0
Hidden=#CPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input13c-Field "ExecuteBatch 1-2"]

[Input13a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=621
Text=#CPUD-Clock_ID#
Hidden=#CPUHideHWiNFO#
[Input13b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#CPUD-Clock_Instance#
Hidden=#CPUHideHWiNFO#
[Input13c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#CPUD-Clock_EntryID#
Hidden=#CPUHideHWiNFO#

[Input13a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=621
W=75
H=13
FocusDismiss=0
DefaultValue=#CPUD-Clock_ID#
Command1=[!SetVariable CPUD-Clock_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUD-Clock_ID [Input13a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input13b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=621
W=35
H=13
FocusDismiss=0
DefaultValue=#CPUD-Clock_Instance#
Command1=[!SetVariable CPUD-Clock_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUD-Clock_Instance [Input13b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
[Input13c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=621
W=75
H=13
FocusDismiss=0
DefaultValue=#CPUD-Clock_EntryID#
Command1=[!SetVariable CPUD-Clock_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUD-Clock_EntryID [Input13c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]


;-- HWiNFO SM Viewer ---------------------------------------------------------------------------------- 

[HWiNFOSMV]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn350x25.png
X=25	
Y=700
LeftMouseUpAction=["#@#Tools\HWiNFOSharedMemoryViewer.exe]
Hidden=#CPUHideHWiNFO#
[HWiNFOSMVText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
StringAlign=Center
X=200
Text="Open HWiNFO Shared Memory Viewer"
Hidden=#CPUHideHWiNFO#


;-- MSI Afterburner -------------------------------------------------------------------------------- 

[MSIAB-BG1]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50
Hidden=#CPUHideMSIAB#

[MSIAB-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=MSI Afterburner
Hidden=#CPUHideMSIAB#

[MSIAB_Status]
Measure=Plugin
Plugin=Process
ProcessName=MSIAfterburner.exe
RegExpSubstitute=1
Substitute="-1":"not running","1":"running"
IfCondition=(MSIAB_Status = 1)
IfTrueAction=[!SetOption MSIAB_StatusText FontColor "0,255,0"]
IfFalseAction=[!SetOption MSIAB_StatusText FontColor "255,0,0"]

[MSIAB_StatusText]
Meter=String
MeterStyle=SettingsStyle-Text
MeasureName=MSIAB_Status
StringAlign=Right
Y=220
X=380
Text=%1
Hidden=#CPUHideMSIAB#

[MSIAB-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160
Hidden=#CPUHideMSIAB#

[MSIAB-LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=240
Text=----- #VarLeftRL# ------
Hidden=#CPUHideMSIAB#

[MSIAB-RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=380
Y=240
Text=------ #VarRightRL# ------
Hidden=#CPUHideMSIAB#

[MSIAB_Image]
Meter=Image
ImageName=#@#Images\General\MSIAB-CPU.png
X=135
Y=275
W=125
Hidden=#CPUHideMSIAB#


;---- Title ----

[MSIAB-Input1-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=145
Y=416
Text=CPU Name:
Hidden=#CPUHideMSIAB#

[MSIAB-Input1-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=416
Text=(%1 = AutoDetect)
Hidden=#CPUHideMSIAB#

[MSIAB-Input1-BG]
Meter=Shape
Shape=Rectangle 150,415,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-Input1-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideMSIAB#

[MSIAB-Input1-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=416
Text=#CPUNameWin#
Hidden=#CPUHideMSIAB#

[MSIAB-Input1-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=416
W=95
H=13
FocusDismiss=0
DefaultValue=#CPUNameWin#
Command1=[!SetVariable CPUNameWin "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPUNameWin [MSIAB-Input1-Field] "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
Hidden=#CPUHideMSIAB#


;---- MSIAB Left Roundline Min/Max ---- 

[MSIAB-InputLR-Max-BG]
Meter=Shape
Shape=Rectangle 15,260,115,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-InputLR-Max-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideMSIAB#

[MSIAB-InputLR-Max-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=261
Text=Max: #CPU_MSIAB_RLLeft_MaxValue# [#SensorUnit[#CPU_RLLeft_ID]]
Hidden=#CPUHideMSIAB#

[MSIAB-InputLR-Max-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=261
W=110
H=13
FocusDismiss=0
DefaultValue=#CPU_MSIAB_RLLeft_MaxValue#
Command1=[!SetVariable CPU_MSIAB_RLLeft_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU_MSIAB_RLLeft_MaxValue [MSIAB-InputLR-Max-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
Hidden=#CPUHideMSIAB#

[MSIAB-InputLR-Min-BG]
Meter=Shape
Shape=Rectangle 15,385,115,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-InputLR-Min-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideMSIAB#

[MSIAB-InputLR-Min-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=386
Text=Min: #CPU_MSIAB_RLLeft_MinValue# [#SensorUnit[#CPU_RLLeft_ID]]
Hidden=#CPUHideMSIAB#

[MSIAB-InputLR-Min-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=386
W=110
H=13
FocusDismiss=0
DefaultValue=#CPU_MSIAB_RLLeft_MinValue#
Command1=[!SetVariable CPU_MSIAB_RLLeft_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU_MSIAB_RLLeft_MinValue [MSIAB-InputLR-Min-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
Hidden=#CPUHideMSIAB#


;---- MSIAB Left Roundline Selection ---- 

[MSIAB_Active_LeftRL]
Measure=Calc
Formula=#CPU_RLLeft_ID#
IfCondition=(MSIAB_Active_LeftRL = 128)
IfTrueAction=[!SetOption MSIAB-Select1 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition2=(MSIAB_Active_LeftRL = 144)
IfTrueAction2=[!SetOption MSIAB-Select2 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition3=(MSIAB_Active_LeftRL = 160)
IfTrueAction3=[!SetOption MSIAB-Select3 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition4=(MSIAB_Active_LeftRL = 256)
IfTrueAction4=[!SetOption MSIAB-Select4 ButtonImage "#@#Images\Buttons\Checkbox1.png"]

[MSIAB-Select1]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=115	
Y=285
LeftMouseUpAction=[!WriteKeyValue Variables CPU_RLLeft_DS "CPU temperature" "#@#MSIAB-Sensors.inc"][!WriteKeyValue Variables CPU_RLLeft_ID 128 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh]
Hidden=#CPUHideMSIAB#

[MSIAB-TextSelect1]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName128#
Hidden=#CPUHideMSIAB#

[MSIAB-Select2]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables CPU_RLLeft_DS "CPU usage" "#@#MSIAB-Sensors.inc"][!WriteKeyValue Variables CPU_RLLeft_ID 144 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh]
Hidden=#CPUHideMSIAB#
[MSIAB-TextSelect2]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName144#
Hidden=#CPUHideMSIAB#

[MSIAB-Select3]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables CPU_RLLeft_DS "CPU clock" "#@#MSIAB-Sensors.inc"][!WriteKeyValue Variables CPU_RLLeft_ID 160 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh]
Hidden=#CPUHideMSIAB#
[MSIAB-TextSelect3]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName160#
Hidden=#CPUHideMSIAB#

[MSIAB-Select4]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables CPU_RLLeft_DS "CPU power" "#@#MSIAB-Sensors.inc"][!WriteKeyValue Variables CPU_RLLeft_ID 256 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh]
Hidden=#CPUHideMSIAB#
[MSIAB-TextSelect4]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName256#
Hidden=#CPUHideMSIAB#


;---- MSIAB Right Roundline Min/Max ---- 

[MSIAB-InputRR-Max-BG]
Meter=Shape
Shape=Rectangle 270,260,115,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-InputRR-Max-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideMSIAB#

[MSIAB-InputRR-Max-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=271
Y=261
Text=Max: #CPU_MSIAB_RLRight_MaxValue# [#SensorUnit[#CPU_RLRight_ID]]
Hidden=#CPUHideMSIAB#

[MSIAB-InputRR-Max-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=261
W=110
H=13
FocusDismiss=0
DefaultValue=#CPU_MSIAB_RLRight_MaxValue#
Command1=[!SetVariable CPU_MSIAB_RLRight_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU_MSIAB_RLRight_MaxValue [MSIAB-InputRR-Max-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
Hidden=#CPUHideMSIAB#

[MSIAB-InputRR-Min-BG]
Meter=Shape
Shape=Rectangle 270,385,115,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-InputRR-Min-Field "ExecuteBatch 1-2"]
Hidden=#CPUHideMSIAB#

[MSIAB-InputRR-Min-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=271
Y=386
Text=Min: #CPU_MSIAB_RLRight_MinValue# [#SensorUnit[#CPU_RLRight_ID]]
Hidden=#CPUHideMSIAB#

[MSIAB-InputRR-Min-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=386
W=110
H=13
FocusDismiss=0
DefaultValue=#CPU_MSIAB_RLRight_MinValue#
Command1=[!SetVariable CPU_MSIAB_RLRight_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables CPU_MSIAB_RLRight_MinValue [MSIAB-InputRR-Min-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Update]
Hidden=#CPUHideMSIAB#

;---- MSIAB Left Roundline Selection ---- 

[MSIAB_Active_RightRL]
Measure=Calc
Formula=#CPU_RLRight_ID#
IfCondition=(MSIAB_Active_RightRL = 128)
IfTrueAction=[!SetOption MSIAB-Select1b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition2=(MSIAB_Active_RightRL = 144)
IfTrueAction2=[!SetOption MSIAB-Select2b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition3=(MSIAB_Active_RightRL = 160)
IfTrueAction3=[!SetOption MSIAB-Select3b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition4=(MSIAB_Active_RightRL = 256)
IfTrueAction4=[!SetOption MSIAB-Select4b ButtonImage "#@#Images\Buttons\Checkbox1.png"]

[MSIAB-Select1b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=270	
Y=285
LeftMouseUpAction=[!WriteKeyValue Variables CPU_RLRight_DS "CPU temperature" "#@#MSIAB-Sensors.inc"][!WriteKeyValue Variables CPU_RLRight_ID 128 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh]
Hidden=#CPUHideMSIAB#

[MSIAB-TextSelect1b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName128#
Hidden=#CPUHideMSIAB#

[MSIAB-Select2b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables CPU_RLRight_DS "CPU usage" "#@#MSIAB-Sensors.inc"][!WriteKeyValue Variables CPU_RLRight_ID 144 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh]
Hidden=#CPUHideMSIAB#
[MSIAB-TextSelect2b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName144#
Hidden=#CPUHideMSIAB#

[MSIAB-Select3b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables CPU_RLRight_DS "CPU clock" "#@#MSIAB-Sensors.inc"][!WriteKeyValue Variables CPU_RLRight_ID 160 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh]
Hidden=#CPUHideMSIAB#
[MSIAB-TextSelect3b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName160#
Hidden=#CPUHideMSIAB#

[MSIAB-Select4b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables CPU_RLRight_DS "CPU power" "#@#MSIAB-Sensors.inc"][!WriteKeyValue Variables CPU_RLRight_ID 256 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\CPU"][!Refresh "#ROOTCONFIG#\Panels\CPU"][!Refresh]
Hidden=#CPUHideMSIAB#
[MSIAB-TextSelect4b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName256#
Hidden=#CPUHideMSIAB#