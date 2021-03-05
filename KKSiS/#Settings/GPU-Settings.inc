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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\GPU" "GPU.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\GPU" "GPU.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-GPUSize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-GPUSize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-GPUSize" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU"]
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
ButtonImage=#@#Images\Buttons\Hide#GPUHideGraph#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "GPUHideGraph" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#GPUHideGraph#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "GPUHideGraph" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh]

[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineName# Label
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#GPUHideRLLabel#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "GPUHideRLLabel" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#GPUHideRLLabel#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "GPUHideRLLabel" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#GPUColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "GPUColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#GPUColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "GPUColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh]


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
LeftMouseUpAction=[!WriteKeyValue Variables "GPUFormat" "Windows" "#@#Variables.inc"][!WriteKeyValue Variables "GPUFormat2" "" "#@#Variables.inc"][!WriteKeyValue Variables "GPUHideWindows" "0" "#@#Variables.inc"][!WriteKeyValue Variables "GPUHideHWiNFO" "1" "#@#Variables.inc"][!WriteKeyValue Variables "GPUHideMSIAB" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh]

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
LeftMouseUpAction=[!WriteKeyValue Variables "GPUFormat" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "GPUFormat2" "" "#@#Variables.inc"][!WriteKeyValue Variables "GPUHideWindows" "1" "#@#Variables.inc"][!WriteKeyValue Variables "GPUHideHWiNFO" "0" "#@#Variables.inc"][!WriteKeyValue Variables "GPUHideMSIAB" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh]

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
LeftMouseUpAction=[!WriteKeyValue Variables "GPUFormat" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "GPUFormat2" "2" "#@#Variables.inc"][!WriteKeyValue Variables "GPUHideWindows" "1" "#@#Variables.inc"][!WriteKeyValue Variables "GPUHideHWiNFO" "0" "#@#Variables.inc"][!WriteKeyValue Variables "GPUHideMSIAB" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh]

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
LeftMouseUpAction=[!WriteKeyValue Variables "GPUFormat" "MSIAB" "#@#Variables.inc"][!WriteKeyValue Variables "GPUFormat2" "" "#@#Variables.inc"][!WriteKeyValue Variables "GPUHideWindows" "1" "#@#Variables.inc"][!WriteKeyValue Variables "GPUHideHWiNFO" "1" "#@#Variables.inc"][!WriteKeyValue Variables "GPUHideMSIAB" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh]

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
Hidden=#GPUHideWindows#

[Windows-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=Windows
Group=Windows
Hidden=#GPUHideWindows#

[Windows-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160
Group=Windows
Hidden=#GPUHideWindows#

[Windows-LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=240
Text=----- #VarLeftRL# ------#CRLF#Name: GPU VRAM
Hidden=#GPUHideWindows#

[Windows-RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=380
Y=240
Text=------ #VarRightRL# ------#CRLF#Name: GPU Usage
Hidden=#GPUHideWindows#

[Windows_Image]
Meter=Image
ImageName=#@#Images\General\Windows-GPU.png
X=135
Y=265
W=125
Hidden=#GPUHideWindows#

;---- Title ----

[Windows-Input1-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=145
Y=386
Text=GPU Name:
Hidden=#GPUHideWindows#

[Windows-Input1-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=386
Text=(%1 = AutoDetect)
Hidden=#GPUHideWindows#

[Windows-Input1-BG]
Meter=Shape
Shape=Rectangle 150,385,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Windows-Input1-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideWindows#

[Windows-Input1-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=386
Text=#GPUNameWin#
Hidden=#GPUHideWindows#

[Windows-Input1-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=386
W=95
H=13
FocusDismiss=0
DefaultValue=#GPUNameWin#
Command1=[!SetVariable GPUNameWin "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPUNameWin [Windows-Input1-Field] "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]




[Windows-Input2-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=145
Y=406
Text=Windows Video Adapter:
Hidden=#GPUHideWindows#

[Windows-Input2-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=406
Text=(0 = Default)
Hidden=#GPUHideWindows#

[Windows-Input2-BG]
Meter=Shape
Shape=Rectangle 150,405,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Windows-Input2-Field "ExecuteBatch 1-6"]
Hidden=#GPUHideWindows#

[Windows-Input2-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=406
Text=#GPUWindowsVideo#
Hidden=#GPUHideWindows#

[Windows-Input2-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=406
W=95
H=13
FocusDismiss=0
DefaultValue=#GPUWindowsVideo#
Command1=[!SetVariable GPUWindowsVideo "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPUWindowsVideo [Windows-Input2-Field] "#@#Windows-Sensors.inc"]
Command3=[!WriteKeyValue Variables GPUVideoAdapter [Windows-Input2-Field] "#ROOTCONFIGPATH#\Circles\GPU\GPU.ini"]
Command4=[!WriteKeyValue Variables GPUVideoAdapter [Windows-Input2-Field] "#ROOTCONFIGPATH#\Panels\GPU\GPU.ini"]
Command5=[!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
Command6=[!Delay 3000][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"]

;-- HWiNFO -------------------------------------------------------------------------------- 

[HWiNFO-BG1]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50
Group=HWiNFO
Hidden=#GPUHideHWiNFO#

[HWiNFO-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=HWiNFO
Group=HWiNFO
Hidden=#GPUHideHWiNFO#

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
Hidden=#GPUHideHWiNFO#

[HWiNFO-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160
Group=HWiNFO
Hidden=#GPUHideHWiNFO#

[HWiNFO_Measure_LeftRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-LeftRL_Id#
HWiNFOSensorInstance=#GPU-LeftRL_Instance#
HWiNFOEntryId		=#GPU-LeftRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1
Hidden=#GPUHideHWiNFO#


[HWiNFO_Measure_RightRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#GPU-RightRL_Id#
HWiNFOSensorInstance=#GPU-RightRL_Instance#
HWiNFOEntryId		=#GPU-RightRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1
Hidden=#GPUHideHWiNFO#

[HWiNFO_Image]
Meter=Image
ImageName=#@#Images\General\HWiNFO-GPU.png
X=135
Y=265
W=125
Hidden=#GPUHideHWiNFO#


;---- Left Roundline ----

[LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
MeasureName=HWiNFO_Measure_LeftRL_Name
X=15
Y=240
Text=----- #VarLeftRL# ------#CRLF#Name: %1
Hidden=#GPUHideHWiNFO#

[Input1a-BG]
Meter=Shape
Shape=Rectangle 15,280,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1a-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideHWiNFO#
[Input1b-BG]
Meter=Shape
Shape=Rectangle 15,300,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1b-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideHWiNFO#
[Input1c-BG]
Meter=Shape
Shape=Rectangle 15,320,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1c-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideHWiNFO#
[Input1d-BG]
Meter=Shape
Shape=Rectangle 15,340,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1d-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideHWiNFO#
[Input1e-BG]
Meter=Shape
Shape=Rectangle 15,360,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1e-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideHWiNFO#
[Input1a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=281
Text=SensorID: #GPU-LeftRL_Id#
Hidden=#GPUHideHWiNFO#
[Input1b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=301
Text=Instance: #GPU-LeftRL_Instance#
Hidden=#GPUHideHWiNFO#
[Input1c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=321
Text=EntryID: #GPU-LeftRL_EntryID#
Hidden=#GPUHideHWiNFO#
[Input1d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=341
Text=Max: #GPU_RLLeft_MaxValue#
Hidden=#GPUHideHWiNFO#
[Input1e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=361
Text=Min: #GPU_RLLeft_MinValue#
Hidden=#GPUHideHWiNFO#

[Input1a-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=281
W=115
H=13
FocusDismiss=0
DefaultValue=#GPU-LeftRL_Id#
Command1=[!SetVariable GPU-LeftRL_Id "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-LeftRL_Id [Input1a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input1b-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=301
W=105
H=13
FocusDismiss=0
DefaultValue=#GPU-LeftRL_Instance#
Command1=[!SetVariable GPU-LeftRL_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-LeftRL_Instance [Input1b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input1c-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=321
W=105
H=13
FocusDismiss=0
DefaultValue=#GPU-LeftRL_EntryID#
Command1=[!SetVariable GPU-LeftRL_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-LeftRL_EntryID [Input1c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input1d-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=341
W=95
H=13
FocusDismiss=0
DefaultValue=#GPU_RLLeft_MaxValue#
Command1=[!SetVariable GPU_RLLeft_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU_RLLeft_MaxValue [Input1d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]

[Input1e-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=361
W=95
H=13
FocusDismiss=0
DefaultValue=#GPU_RLLeft_MinValue#
Command1=[!SetVariable GPU_RLLeft_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU_RLLeft_MinValue [Input1e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]


;---- Right Roundline ----

[RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=380
Y=240
Text=------ #VarRightRL# ------#CRLF#Name: %1
Hidden=#GPUHideHWiNFO#

[Input2a-BG]
Meter=Shape
Shape=Rectangle 260,280,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2a-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideHWiNFO#
[Input2b-BG]
Meter=Shape
Shape=Rectangle 270,300,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2b-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideHWiNFO#
[Input2c-BG]
Meter=Shape
Shape=Rectangle 270,320,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2c-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideHWiNFO#
[Input2d-BG]
Meter=Shape
Shape=Rectangle 280,340,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2d-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideHWiNFO#
[Input2e-BG]
Meter=Shape
Shape=Rectangle 280,360,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2e-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideHWiNFO#
[Input2a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=281
Text=SensorID: #GPU-RightRL_Id#
Hidden=#GPUHideHWiNFO#
[Input2b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=301
Text=Instance: #GPU-RightRL_Instance#
Hidden=#GPUHideHWiNFO#
[Input2c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=321
Text=EntryID: #GPU-RightRL_EntryID#
Hidden=#GPUHideHWiNFO#
[Input2d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=341
Text=Max: #GPU_RLRight_MaxValue#
Hidden=#GPUHideHWiNFO#
[Input2e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=361
Text=Min: #GPU_RLRight_MinValue#
Hidden=#GPUHideHWiNFO#

[Input2a-Field]
Measure=Plugin
Plugin=InputText
X=261
Y=281
W=115
H=13
FocusDismiss=0
DefaultValue=#GPU-RightRL_Id#
Command1=[!SetVariable GPU-RightRL_Id "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-RightRL_Id [Input2a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input2b-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=301
W=105
H=13
FocusDismiss=0
DefaultValue=#GPU-RightRL_Instance#
Command1=[!SetVariable GPU-RightRL_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-RightRL_Instance [Input2b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input2c-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=321
W=105
H=13
FocusDismiss=0
DefaultValue=#GPU-RightRL_EntryID#
Command1=[!SetVariable GPU-RightRL_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-RightRL_EntryID [Input2c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input2d-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=341
W=95
H=13
FocusDismiss=0
DefaultValue=#GPU_RLRight_MaxValue#
Command1=[!SetVariable GPU_RLRight_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU_RLRight_MaxValue [Input2d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]

[Input2e-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=361
W=95
H=13
FocusDismiss=0
DefaultValue=#GPU_RLRight_MinValue#
Command1=[!SetVariable GPU_RLRight_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU_RLRight_MinValue [Input2e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]


;---- Title ----

[Input3-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=145
Y=386
Text=GPU Name:
Hidden=#GPUHideHWiNFO#

[Input3-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=386
Text=(%1 = AutoDetect)
Hidden=#GPUHideHWiNFO#

[Input3-BG]
Meter=Shape
Shape=Rectangle 150,385,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input3-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideHWiNFO#

[Input3-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=386
Text=#GPUName#
Hidden=#GPUHideHWiNFO#

[Input3-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=386
W=95
H=13
FocusDismiss=0
DefaultValue=#GPUName#
Command1=[!SetVariable GPUName "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPUName [Input3-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]


;---- HWiNFO Sensors

[HWiNFO-Divider2]
Meter=Shape
Shape=Rectangle 12,410,375,2,0 | Fill Color 160,160,160
Group=HWiNFO
Hidden=#GPUHideHWiNFO#

[HWiNFO-Sensor-Headline]
Meter=String
MeterStyle=SettingsStyle-Text
Hidden=#GPUHideHWiNFO#
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
Text="GPU Core Load"
Hidden=#GPUHideHWiNFO#

[Input4a-BG]
Meter=Shape
Shape=Rectangle 160,440,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4a-Field "ExecuteBatch 1-2"]
[Input4b-BG]
Meter=Shape
Shape=Rectangle 250,440,40,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4b-Field "ExecuteBatch 1-2"]
[Input4c-BG]
Meter=Shape
Shape=Rectangle 300,440,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4c-Field "ExecuteBatch 1-2"]

[Input4a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=441
Text=#GPU-CoreLoad_ID#
Hidden=#GPUHideHWiNFO#
[Input4b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU-CoreLoad_Instance#
Hidden=#GPUHideHWiNFO#
[Input4c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU-CoreLoad_EntryID#
Hidden=#GPUHideHWiNFO#

[Input4a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=441
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-CoreLoad_ID#
Command1=[!SetVariable GPU-CoreLoad_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-CoreLoad_ID [Input4a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input4b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=441
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU-CoreLoad_Instance#
Command1=[!SetVariable GPU-CoreLoad_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-CoreLoad_Instance [Input4b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input4c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=441
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-CoreLoad_EntryID#
Command1=[!SetVariable GPU-CoreLoad_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-CoreLoad_EntryID [Input4c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]


[Input5-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=461
Text="GPU Temperature"
Hidden=#GPUHideHWiNFO#

[Input5a-BG]
Meter=Shape
Shape=Rectangle 160,460,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5a-Field "ExecuteBatch 1-2"]
[Input5b-BG]
Meter=Shape
Shape=Rectangle 250,460,40,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5b-Field "ExecuteBatch 1-2"]
[Input5c-BG]
Meter=Shape
Shape=Rectangle 300,460,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5c-Field "ExecuteBatch 1-2"]

[Input5a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=461
Text=#GPU-Temp_ID#
Hidden=#GPUHideHWiNFO#
[Input5b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU-Temp_Instance#
Hidden=#GPUHideHWiNFO#
[Input5c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU-Temp_EntryID#
Hidden=#GPUHideHWiNFO#

[Input5a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=461
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-Temp_ID#
Command1=[!SetVariable GPU-Temp_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-Temp_ID [Input5a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input5b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=461
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU-Temp_Instance#
Command1=[!SetVariable GPU-Temp_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-Temp_Instance [Input5b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input5c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=461
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-Temp_EntryID#
Command1=[!SetVariable GPU-Temp_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-Temp_EntryID [Input5c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]


[Input6-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=481
Text="GPU FAN1"
Hidden=#GPUHideHWiNFO#

[Input6a-BG]
Meter=Shape
Shape=Rectangle 160,480,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6a-Field "ExecuteBatch 1-2"]
[Input6b-BG]
Meter=Shape
Shape=Rectangle 250,480,40,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6b-Field "ExecuteBatch 1-2"]
[Input6c-BG]
Meter=Shape
Shape=Rectangle 300,480,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6c-Field "ExecuteBatch 1-2"]

[Input6a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=481
Text=#GPU-FAN1_ID#
Hidden=#GPUHideHWiNFO#
[Input6b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU-FAN1_Instance#
Hidden=#GPUHideHWiNFO#
[Input6c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU-FAN1_EntryID#
Hidden=#GPUHideHWiNFO#

[Input6a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=481
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-FAN1_ID#
Command1=[!SetVariable GPU-FAN1_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-FAN1_ID [Input6a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input6b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=481
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU-FAN1_Instance#
Command1=[!SetVariable GPU-FAN1_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-FAN1_Instance [Input6b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input6c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=481
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-FAN1_EntryID#
Command1=[!SetVariable GPU-FAN1_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-FAN1_EntryID [Input6c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]


[Input7-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=501
Text="GPU FAN2"
Hidden=#GPUHideHWiNFO#

[Input7a-BG]
Meter=Shape
Shape=Rectangle 160,500,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7a-Field "ExecuteBatch 1-2"]
[Input7b-BG]
Meter=Shape
Shape=Rectangle 250,500,40,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7b-Field "ExecuteBatch 1-2"]
[Input7c-BG]
Meter=Shape
Shape=Rectangle 300,500,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7c-Field "ExecuteBatch 1-2"]

[Input7a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=501
Text=#GPU-FAN2_ID#
Hidden=#GPUHideHWiNFO#
[Input7b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU-FAN2_Instance#
Hidden=#GPUHideHWiNFO#
[Input7c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU-FAN2_EntryID#
Hidden=#GPUHideHWiNFO#

[Input7a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=501
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-FAN2_ID#
Command1=[!SetVariable GPU-FAN2_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-FAN2_ID [Input7a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input7b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=501
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU-FAN2_Instance#
Command1=[!SetVariable GPU-FAN2_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-FAN2_Instance [Input7b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input7c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=501
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-FAN2_EntryID#
Command1=[!SetVariable GPU-FAN2_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-FAN2_EntryID [Input7c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]


[Input8-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=521
Text="GPU Dedicated Memory"
Hidden=#GPUHideHWiNFO#

[Input8a-BG]
Meter=Shape
Shape=Rectangle 160,520,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input8a-Field "ExecuteBatch 1-2"]
[Input8b-BG]
Meter=Shape
Shape=Rectangle 250,520,40,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input8b-Field "ExecuteBatch 1-2"]
[Input8c-BG]
Meter=Shape
Shape=Rectangle 300,520,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input8c-Field "ExecuteBatch 1-2"]

[Input8a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=521
Text=#GPU-VRAM_ID#
Hidden=#GPUHideHWiNFO#
[Input8b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU-VRAM_Instance#
Hidden=#GPUHideHWiNFO#
[Input8c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU-VRAM_EntryID#
Hidden=#GPUHideHWiNFO#

[Input8a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=521
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-VRAM_ID#
Command1=[!SetVariable GPU-VRAM_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-VRAM_ID [Input8a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input8b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=521
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU-VRAM_Instance#
Command1=[!SetVariable GPU-VRAM_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-VRAM_Instance [Input8b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input8c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=521
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-VRAM_EntryID#
Command1=[!SetVariable GPU-VRAM_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-VRAM_EntryID [Input8c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]

[Input9-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=541
Text="GPU Power"
Hidden=#GPUHideHWiNFO#

[Input9a-BG]
Meter=Shape
Shape=Rectangle 160,540,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input9a-Field "ExecuteBatch 1-2"]
[Input9b-BG]
Meter=Shape
Shape=Rectangle 250,540,40,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input9b-Field "ExecuteBatch 1-2"]
[Input9c-BG]
Meter=Shape
Shape=Rectangle 300,540,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input9c-Field "ExecuteBatch 1-2"]

[Input9a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=541
Text=#GPU-Power_ID#
Hidden=#GPUHideHWiNFO#
[Input9b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU-Power_Instance#
Hidden=#GPUHideHWiNFO#
[Input9c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU-Power_EntryID#
Hidden=#GPUHideHWiNFO#

[Input9a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=541
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-Power_ID#
Command1=[!SetVariable GPU-Power_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-Power_ID [Input9a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input9b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=541
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU-Power_Instance#
Command1=[!SetVariable GPU-Power_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-Power_Instance [Input9b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input9c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=541
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-Power_EntryID#
Command1=[!SetVariable GPU-Power_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-Power_EntryID [Input9c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]


[Input10-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=561
Text="GPU Clock"
Hidden=#GPUHideHWiNFO#

[Input10a-BG]
Meter=Shape
Shape=Rectangle 160,560,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input10a-Field "ExecuteBatch 1-2"]
[Input10b-BG]
Meter=Shape
Shape=Rectangle 250,560,40,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input10b-Field "ExecuteBatch 1-2"]
[Input10c-BG]
Meter=Shape
Shape=Rectangle 300,560,80,15,3 | Fill Color 0,0,0
Hidden=#GPUHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input10c-Field "ExecuteBatch 1-2"]

[Input10a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=561
Text=#GPU-Clock_ID#
Hidden=#GPUHideHWiNFO#
[Input10b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU-Clock_Instance#
Hidden=#GPUHideHWiNFO#
[Input10c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU-Clock_EntryID#
Hidden=#GPUHideHWiNFO#

[Input10a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=561
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-Clock_ID#
Command1=[!SetVariable GPU-Clock_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-Clock_ID [Input10a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input10b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=561
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU-Clock_Instance#
Command1=[!SetVariable GPU-Clock_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-Clock_Instance [Input10b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
[Input10c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=561
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-Clock_EntryID#
Command1=[!SetVariable GPU-Clock_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-Clock_EntryID [Input10c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]


;-- HWiNFO SM Viewer ---------------------------------------------------------------------------------- 

[HWiNFOSMV]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn350x25.png
X=25	
Y=700
LeftMouseUpAction=["#@#Tools\HWiNFOSharedMemoryViewer.exe]
Hidden=#GPUHideHWiNFO#
[HWiNFOSMVText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
StringAlign=Center
X=200
Text="Open HWiNFO Shared Memory Viewer"
Hidden=#GPUHideHWiNFO#


;-- MSI Afterburner -------------------------------------------------------------------------------- 

[MSIAB-BG1]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50
Hidden=#GPUHideMSIAB#

[MSIAB-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=MSI Afterburner
Hidden=#GPUHideMSIAB#

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
Hidden=#GPUHideMSIAB#

[MSIAB-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160
Hidden=#GPUHideMSIAB#

[MSIAB-LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=240
Text=----- #VarLeftRL# ------
Hidden=#GPUHideMSIAB#

[MSIAB-RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=380
Y=240
Text=------ #VarRightRL# ------
Hidden=#GPUHideMSIAB#

[MSIAB_Image]
Meter=Image
ImageName=#@#Images\General\MSIAB-GPU.png
X=137
Y=275
W=125
Hidden=#GPUHideMSIAB#


;---- Title ----

[MSIAB-Input1-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=145
Y=566
Text=GPU Name:
Hidden=#GPUHideMSIAB#

[MSIAB-Input1-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=566
Text=(%1 = AutoDetect)
Hidden=#GPUHideMSIAB#

[MSIAB-Input1-BG]
Meter=Shape
Shape=Rectangle 150,565,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-Input1-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideMSIAB#

[MSIAB-Input1-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=566
Text=#GPUNameMSIAB#
Hidden=#GPUHideMSIAB#

[MSIAB-Input1-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=566
W=95
H=13
FocusDismiss=0
DefaultValue=#GPUNameMSIAB#
Command1=[!SetVariable GPUNameMSIAB "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPUNameMSIAB [MSIAB-Input1-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
Hidden=#GPUHideMSIAB#


;---- MSIAB Left Roundline Min/Max ---- 

[MSIAB-InputLR-Max-BG]
Meter=Shape
Shape=Rectangle 15,260,115,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-InputLR-Max-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideMSIAB#

[MSIAB-InputLR-Max-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=261
Text=Max: #GPU_MSIAB_RLLeft_MaxValue# [#SensorUnit[#GPU_RLLeft_ID]]
Hidden=#GPUHideMSIAB#

[MSIAB-InputLR-Max-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=261
W=110
H=13
FocusDismiss=0
DefaultValue=#GPU_MSIAB_RLLeft_MaxValue#
Command1=[!SetVariable GPU_MSIAB_RLLeft_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU_MSIAB_RLLeft_MaxValue [MSIAB-InputLR-Max-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
Hidden=#GPUHideMSIAB#

[MSIAB-InputLR-Min-BG]
Meter=Shape
Shape=Rectangle 15,535,115,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-InputLR-Min-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideMSIAB#

[MSIAB-InputLR-Min-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=536
Text=Min: #GPU_MSIAB_RLLeft_MinValue# [#SensorUnit[#GPU_RLLeft_ID]]
Hidden=#GPUHideMSIAB#

[MSIAB-InputLR-Min-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=536
W=110
H=13
FocusDismiss=0
DefaultValue=#GPU_MSIAB_RLLeft_MinValue#
Command1=[!SetVariable GPU_MSIAB_RLLeft_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU_MSIAB_RLLeft_MinValue [MSIAB-InputLR-Min-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
Hidden=#GPUHideMSIAB#


;---- MSIAB Left Roundline Selection ---- 

[MSIAB_Active_LeftRL]
Measure=Calc
Formula=#GPU_RLLeft_ID#
IfCondition=(MSIAB_Active_LeftRL = 0)
IfTrueAction=[!SetOption MSIAB-Select1 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition2=(MSIAB_Active_LeftRL = 16)
IfTrueAction2=[!SetOption MSIAB-Select2 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition3=(MSIAB_Active_LeftRL = 18)
IfTrueAction3=[!SetOption MSIAB-Select3 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition4=(MSIAB_Active_LeftRL = 20)
IfTrueAction4=[!SetOption MSIAB-Select4 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition5=(MSIAB_Active_LeftRL = 32)
IfTrueAction5=[!SetOption MSIAB-Select5 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition6=(MSIAB_Active_LeftRL = 34)
IfTrueAction6=[!SetOption MSIAB-Select6 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition7=(MSIAB_Active_LeftRL = 48)
IfTrueAction7=[!SetOption MSIAB-Select7 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition8=(MSIAB_Active_LeftRL = 49)
IfTrueAction8=[!SetOption MSIAB-Select8 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition9=(MSIAB_Active_LeftRL = 64)
IfTrueAction9=[!SetOption MSIAB-Select9 ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition10=(MSIAB_Active_LeftRL = 96)
IfTrueAction10=[!SetOption MSIAB-Select10 ButtonImage "#@#Images\Buttons\Checkbox1.png"]

[MSIAB-Select1]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=115	
Y=285
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLLeft_ID 0 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#

[MSIAB-TextSelect1]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName0#
Hidden=#GPUHideMSIAB#

[MSIAB-Select2]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLLeft_ID 16 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect2]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName16#
Hidden=#GPUHideMSIAB#

[MSIAB-Select3]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLLeft_ID 18 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect3]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName18#
Hidden=#GPUHideMSIAB#

[MSIAB-Select4]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLLeft_ID 20 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect4]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName20#
Hidden=#GPUHideMSIAB#

[MSIAB-Select5]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLLeft_ID 32 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect5]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName32#
Hidden=#GPUHideMSIAB#

[MSIAB-Select6]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLLeft_ID 34 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect6]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName34#
Hidden=#GPUHideMSIAB#

[MSIAB-Select7]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLLeft_ID 48 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect7]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName48#
Hidden=#GPUHideMSIAB#

[MSIAB-Select8]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLLeft_ID 49 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect8]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName49#
Hidden=#GPUHideMSIAB#

[MSIAB-Select9]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLLeft_ID 64 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect9]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName64#
Hidden=#GPUHideMSIAB#

[MSIAB-Select10]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=5r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLLeft_ID 96 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect10]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=-5r
Y=0r
Text=#SensorName96#
Hidden=#GPUHideMSIAB#


;---- MSIAB Right Roundline Min/Max ---- 

[MSIAB-InputRR-Max-BG]
Meter=Shape
Shape=Rectangle 270,260,115,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-InputRR-Max-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideMSIAB#

[MSIAB-InputRR-Max-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=271
Y=261
Text=Max: #GPU_MSIAB_RLRight_MaxValue# [#SensorUnit[#GPU_RLRight_ID]]
Hidden=#GPUHideMSIAB#

[MSIAB-InputRR-Max-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=261
W=110
H=13
FocusDismiss=0
DefaultValue=#GPU_MSIAB_RLRight_MaxValue#
Command1=[!SetVariable GPU_MSIAB_RLRight_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU_MSIAB_RLRight_MaxValue [MSIAB-InputRR-Max-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
Hidden=#GPUHideMSIAB#

[MSIAB-InputRR-Min-BG]
Meter=Shape
Shape=Rectangle 270,535,115,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MSIAB-InputRR-Min-Field "ExecuteBatch 1-2"]
Hidden=#GPUHideMSIAB#

[MSIAB-InputRR-Min-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=271
Y=536
Text=Min: #GPU_MSIAB_RLRight_MinValue# [#SensorUnit[#GPU_RLRight_ID]]
Hidden=#GPUHideMSIAB#

[MSIAB-InputRR-Min-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=536
W=110
H=13
FocusDismiss=0
DefaultValue=#GPU_MSIAB_RLRight_MinValue#
Command1=[!SetVariable GPU_MSIAB_RLRight_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU_MSIAB_RLRight_MinValue [MSIAB-InputRR-Min-Field] "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Update]
Hidden=#GPUHideMSIAB#

;---- MSIAB Left Roundline Selection ---- 

[MSIAB_Active_RightRL]
Measure=Calc
Formula=#GPU_RLRight_ID#
IfCondition=(MSIAB_Active_RightRL = 0)
IfTrueAction=[!SetOption MSIAB-Select1b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition2=(MSIAB_Active_RightRL = 16)
IfTrueAction2=[!SetOption MSIAB-Select2b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition3=(MSIAB_Active_RightRL = 18)
IfTrueAction3=[!SetOption MSIAB-Select3b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition4=(MSIAB_Active_RightRL = 20)
IfTrueAction4=[!SetOption MSIAB-Select4b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition5=(MSIAB_Active_RightRL = 32)
IfTrueAction5=[!SetOption MSIAB-Select5b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition6=(MSIAB_Active_RightRL = 34)
IfTrueAction6=[!SetOption MSIAB-Select6b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition7=(MSIAB_Active_RightRL = 48)
IfTrueAction7=[!SetOption MSIAB-Select7b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition8=(MSIAB_Active_RightRL = 49)
IfTrueAction8=[!SetOption MSIAB-Select8b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition9=(MSIAB_Active_RightRL = 64)
IfTrueAction9=[!SetOption MSIAB-Select9b ButtonImage "#@#Images\Buttons\Checkbox1.png"]
IfCondition10=(MSIAB_Active_RightRL = 96)
IfTrueAction10=[!SetOption MSIAB-Select10b ButtonImage "#@#Images\Buttons\Checkbox1.png"]

[MSIAB-Select1b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=270	
Y=285
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLRight_ID 0 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#

[MSIAB-TextSelect1b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName0#
Hidden=#GPUHideMSIAB#

[MSIAB-Select2b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLRight_ID 16 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect2b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName16#
Hidden=#GPUHideMSIAB#

[MSIAB-Select3b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLRight_ID 18 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect3b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName18#
Hidden=#GPUHideMSIAB#

[MSIAB-Select4b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLRight_ID 20 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect4b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName20#
Hidden=#GPUHideMSIAB#

[MSIAB-Select5b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLRight_ID 32 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect5b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName32#
Hidden=#GPUHideMSIAB#

[MSIAB-Select6b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLRight_ID 34 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect6b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName34#
Hidden=#GPUHideMSIAB#

[MSIAB-Select7b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLRight_ID 48 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect7b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName48#
Hidden=#GPUHideMSIAB#

[MSIAB-Select8b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLRight_ID 49 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect8b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName49#
Hidden=#GPUHideMSIAB#

[MSIAB-Select9b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLRight_ID 64 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect9b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName64#
Hidden=#GPUHideMSIAB#

[MSIAB-Select10b]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=-20r	
Y=25r
LeftMouseUpAction=[!WriteKeyValue Variables GPU_RLRight_ID 96 "#@#MSIAB-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\GPU"][!Refresh "#ROOTCONFIG#\Panels\GPU"][!Refresh]
Hidden=#GPUHideMSIAB#
[MSIAB-TextSelect10b]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=#SensorName96#
Hidden=#GPUHideMSIAB#