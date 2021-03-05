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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\Drive5" "Drive5.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\Drive5" "Drive5.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-Drive5Size" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-Drive5Size" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-Drive5Size" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"]
[Button2cText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarBig#


;---- Options ----

[Background3]
Meter=Shape
Shape=Rectangle 230,35,160,170,3 | Fill Color 50,50,50

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
ButtonImage=#@#Images\Buttons\Hide#Drive5HideGraph#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Drive5HideGraph" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#Drive5HideGraph#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Drive5HideGraph" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]

[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineName# Label
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#Drive5HideRLLabel#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Drive5HideRLLabel" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#Drive5HideRLLabel#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Drive5HideRLLabel" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Drive5ColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Drive5ColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Drive5ColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Drive5ColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]

[ButtonDescription34]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarShowPercent#
X=235
Y=20r
[Button34a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Drive5ShowPercentage#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Drive5ShowPercentage" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]
[Button34b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Drive5ShowPercentage#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Drive5ShowPercentage" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]

[ButtonDescription35]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarShowFreeSpace#
X=235
Y=20r
[Button35a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Drive5ShowFreeSpace#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Drive5ShowFreeSpace" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]
[Button35b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Drive5ShowFreeSpace#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Drive5ShowFreeSpace" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]

[ButtonDescription36]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarDriveSSDHDD#
X=235
Y=20r
[Button36a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Drive5SSD#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Drive5SSD" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]
[Button36b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#Drive5SSD#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "Drive5SSD" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]


[DriveLetter-Description]
Meter=String
MeterStyle=SettingsStyle-Text
X=235
Y=20r
Text=#VarDriveLetter#
[DriveLetter-BG]
Meter=Shape
Shape=Rectangle 352,185,32,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure DriveLetter-Field "ExecuteBatch 1-2"]
[DriveLetter-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=355
Y=186
Text=#Drive5Letter#
ToolTipText=#VarCapitalLetter#
[DriveLetter-Field]
Measure=Plugin
Plugin=InputText
X=354
Y=186
W=28
H=13
FocusDismiss=0
DefaultValue=#Drive5Letter#
Command1=[!SetVariable Drive5Letter "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5Letter [DriveLetter-Field] "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]



;-- Technology -------------------------------------------------------------------------------- 

[BG3]
Meter=Shape
Shape=Rectangle 10,140,210,65,3 | Fill Color 50,50,50

[T3Text]
Meter=String
MeterStyle=SettingsStyle-Text
Y=145
Text=#VarTechnology#

[T3Divider]
Meter=Shape
Shape=Rectangle 12,160,206,2,0 | Fill Color 160,160,160

[Technology1Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn60x25.png
X=20
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "Drive5Format" "Windows" "#@#Variables.inc"][!WriteKeyValue Variables "Drive5Format2" "" "#@#Variables.inc"][!WriteKeyValue Variables "Drive5HideWindows" "0" "#@#Variables.inc"][!WriteKeyValue Variables "Drive5HideHWiNFO" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]

[Technology1Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=30r
Y=6r
Text=Windows

[Technology2Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn60x25.png
X=35r
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "Drive5Format" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "Drive5Format2" "" "#@#Variables.inc"][!WriteKeyValue Variables "Drive5HideWindows" "1" "#@#Variables.inc"][!WriteKeyValue Variables "Drive5HideHWiNFO" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]

[Technology2Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=30r
Y=6r
Text=HWiNFO 1

[Technology3Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn60x25.png
X=35r
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "Drive5Format" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "Drive5Format2" "2" "#@#Variables.inc"][!WriteKeyValue Variables "Drive5HideWindows" "1" "#@#Variables.inc"][!WriteKeyValue Variables "Drive5HideHWiNFO" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]

[Technology3Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=30r
Y=6r
Text=HWiNFO 2


;-- Windows -------------------------------------------------------------------------------- 

[Windows-BG1]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50
Group=Windows
Hidden=#Drive5HideWindows#

[Windows-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=Windows
Group=Windows
Hidden=#Drive5HideWindows#

[Windows-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160
Group=Windows
Hidden=#Drive5HideWindows#

[Windows-LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=240
Text=----- #VarLeftRL# ------#CRLF#Name: Drive5 Space
Hidden=#Drive5HideWindows#

[Windows-RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=380
Y=240
Text=------ #VarRightRL# ------#CRLF#Name: Drive5 Space
Hidden=#Drive5HideWindows#

[Windows_Image]
Meter=Image
ImageName=#@#Images\General\Windows-Drive.png
X=135
Y=265
W=125
Hidden=#Drive5HideWindows#


;---- Title ----

[Windows-Input1-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=145
Y=386
Text=Drive5 Name:
Hidden=#Drive5HideWindows#

[Windows-Input1-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=386
Text=(%1 = AutoDetect)
Hidden=#Drive5HideWindows#

[Windows-Input1-BG]
Meter=Shape
Shape=Rectangle 150,385,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Windows-Input1-Field "ExecuteBatch 1-2"]
Hidden=#Drive5HideWindows#

[Windows-Input1-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=386
Text=#Drive5NameWin#
Hidden=#Drive5HideWindows#

[Windows-Input1-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=386
W=95
H=13
FocusDismiss=0
DefaultValue=#Drive5NameWin#
Command1=[!SetVariable Drive5NameWin "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5NameWin [Windows-Input1-Field] "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]


;-- HWiNFO -------------------------------------------------------------------------------- 

[HWiNFO-BG1]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50
Group=HWiNFO
Hidden=#Drive5HideHWiNFO#

[HWiNFO-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=HWiNFO
Group=HWiNFO
Hidden=#Drive5HideHWiNFO#

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
Hidden=#Drive5HideHWiNFO#

[HWiNFO-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160
Group=HWiNFO
Hidden=#Drive5HideHWiNFO#

[HWiNFO_Measure_LeftRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive5-LeftRL_Id#
HWiNFOSensorInstance=#Drive5-LeftRL_Instance#
HWiNFOEntryId		=#Drive5-LeftRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1
Hidden=#Drive5HideHWiNFO#


[HWiNFO_Measure_RightRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#Drive5-RightRL_Id#
HWiNFOSensorInstance=#Drive5-RightRL_Instance#
HWiNFOEntryId		=#Drive5-RightRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1
Hidden=#Drive5HideHWiNFO#

[HWiNFO_Image]
Meter=Image
ImageName=#@#Images\General\HWiNFO-Drive.png
X=135
Y=265
W=125
Hidden=#Drive5HideHWiNFO#


;---- Left Roundline ----

[LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
MeasureName=HWiNFO_Measure_LeftRL_Name
X=15
Y=240
Text=----- #VarLeftRL# ------#CRLF#Name: %1
Hidden=#Drive5HideHWiNFO#

[Input1a-BG]
Meter=Shape
Shape=Rectangle 15,280,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1a-Field "ExecuteBatch 1-2"]
Hidden=#Drive5HideHWiNFO#
[Input1b-BG]
Meter=Shape
Shape=Rectangle 15,300,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1b-Field "ExecuteBatch 1-2"]
Hidden=#Drive5HideHWiNFO#
[Input1c-BG]
Meter=Shape
Shape=Rectangle 15,320,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1c-Field "ExecuteBatch 1-2"]
Hidden=#Drive5HideHWiNFO#
[Input1d-BG]
Meter=Shape
Shape=Rectangle 15,340,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1d-Field "ExecuteBatch 1-2"]
Hidden=#Drive5HideHWiNFO#
[Input1e-BG]
Meter=Shape
Shape=Rectangle 15,360,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1e-Field "ExecuteBatch 1-2"]
Hidden=#Drive5HideHWiNFO#
[Input1a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=281
Text=SensorID: #Drive5-LeftRL_Id#
Hidden=#Drive5HideHWiNFO#
[Input1b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=301
Text=Instance: #Drive5-LeftRL_Instance#
Hidden=#Drive5HideHWiNFO#
[Input1c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=321
Text=EntryID: #Drive5-LeftRL_EntryID#
Hidden=#Drive5HideHWiNFO#
[Input1d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=341
Text=Max: #Drive5_RLLeft_MaxValue#
Hidden=#Drive5HideHWiNFO#
[Input1e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=361
Text=Min: #Drive5_RLLeft_MinValue#
Hidden=#Drive5HideHWiNFO#

[Input1a-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=281
W=115
H=13
FocusDismiss=0
DefaultValue=#Drive5-LeftRL_Id#
Command1=[!SetVariable Drive5-LeftRL_Id "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-LeftRL_Id [Input1a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input1b-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=301
W=105
H=13
FocusDismiss=0
DefaultValue=#Drive5-LeftRL_Instance#
Command1=[!SetVariable Drive5-LeftRL_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-LeftRL_Instance [Input1b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input1c-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=321
W=105
H=13
FocusDismiss=0
DefaultValue=#Drive5-LeftRL_EntryID#
Command1=[!SetVariable Drive5-LeftRL_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-LeftRL_EntryID [Input1c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input1d-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=341
W=95
H=13
FocusDismiss=0
DefaultValue=#Drive5_RLLeft_MaxValue#
Command1=[!SetVariable Drive5_RLLeft_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5_RLLeft_MaxValue [Input1d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]

[Input1e-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=361
W=95
H=13
FocusDismiss=0
DefaultValue=#Drive5_RLLeft_MinValue#
Command1=[!SetVariable Drive5_RLLeft_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5_RLLeft_MinValue [Input1e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]


;---- Right Roundline ----

[RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=380
Y=240
Text=------ #VarRightRL# ------#CRLF#Name: %1
Hidden=#Drive5HideHWiNFO#

[Input2a-BG]
Meter=Shape
Shape=Rectangle 260,280,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2a-Field "ExecuteBatch 1-2"]
Hidden=#Drive5HideHWiNFO#
[Input2b-BG]
Meter=Shape
Shape=Rectangle 270,300,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2b-Field "ExecuteBatch 1-2"]
Hidden=#Drive5HideHWiNFO#
[Input2c-BG]
Meter=Shape
Shape=Rectangle 270,320,110,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2c-Field "ExecuteBatch 1-2"]
Hidden=#Drive5HideHWiNFO#
[Input2d-BG]
Meter=Shape
Shape=Rectangle 280,340,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2d-Field "ExecuteBatch 1-2"]
Hidden=#Drive5HideHWiNFO#
[Input2e-BG]
Meter=Shape
Shape=Rectangle 280,360,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2e-Field "ExecuteBatch 1-2"]
Hidden=#Drive5HideHWiNFO#
[Input2a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=281
Text=SensorID: #Drive5-RightRL_Id#
Hidden=#Drive5HideHWiNFO#
[Input2b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=301
Text=Instance: #Drive5-RightRL_Instance#
Hidden=#Drive5HideHWiNFO#
[Input2c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=321
Text=EntryID: #Drive5-RightRL_EntryID#
Hidden=#Drive5HideHWiNFO#
[Input2d-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=341
Text=Max: #Drive5_RLRight_MaxValue#
Hidden=#Drive5HideHWiNFO#
[Input2e-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=361
Text=Min: #Drive5_RLRight_MinValue#
Hidden=#Drive5HideHWiNFO#

[Input2a-Field]
Measure=Plugin
Plugin=InputText
X=261
Y=281
W=115
H=13
FocusDismiss=0
DefaultValue=#Drive5-RightRL_Id#
Command1=[!SetVariable Drive5-RightRL_Id "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-RightRL_Id [Input2a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input2b-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=301
W=105
H=13
FocusDismiss=0
DefaultValue=#Drive5-RightRL_Instance#
Command1=[!SetVariable Drive5-RightRL_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-RightRL_Instance [Input2b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input2c-Field]
Measure=Plugin
Plugin=InputText
X=271
Y=321
W=105
H=13
FocusDismiss=0
DefaultValue=#Drive5-RightRL_EntryID#
Command1=[!SetVariable Drive5-RightRL_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-RightRL_EntryID [Input2c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input2d-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=341
W=95
H=13
FocusDismiss=0
DefaultValue=#Drive5_RLRight_MaxValue#
Command1=[!SetVariable Drive5_RLRight_MaxValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5_RLRight_MaxValue [Input2d-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]

[Input2e-Field]
Measure=Plugin
Plugin=InputText
X=281
Y=361
W=95
H=13
FocusDismiss=0
DefaultValue=#Drive5_RLRight_MinValue#
Command1=[!SetVariable Drive5_RLRight_MinValue "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5_RLRight_MinValue [Input2e-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]


;---- Title ----

[Input3-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=145
Y=386
Text=Drive5 Name:
Hidden=#Drive5HideHWiNFO#

[Input3-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=386
Text=(%1 = AutoDetect)
Hidden=#Drive5HideHWiNFO#

[Input3-BG]
Meter=Shape
Shape=Rectangle 150,385,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input3-Field "ExecuteBatch 1-2"]
Hidden=#Drive5HideHWiNFO#

[Input3-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=386
Text=#Drive5Name#
Hidden=#Drive5HideHWiNFO#

[Input3-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=386
W=95
H=13
FocusDismiss=0
DefaultValue=#Drive5Name#
Command1=[!SetVariable Drive5Name "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5Name [Input3-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]


;---- HWiNFO Sensors

[HWiNFO-Divider2]
Meter=Shape
Shape=Rectangle 12,410,375,2,0 | Fill Color 160,160,160
Group=HWiNFO
Hidden=#Drive5HideHWiNFO#

[HWiNFO-Sensor-Headline]
Meter=String
MeterStyle=SettingsStyle-Text
Hidden=#Drive5HideHWiNFO#
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
Text="Drive5 Temperature"
Hidden=#Drive5HideHWiNFO#

[Input4a-BG]
Meter=Shape
Shape=Rectangle 160,440,80,15,3 | Fill Color 0,0,0
Hidden=#Drive5HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4a-Field "ExecuteBatch 1-2"]
[Input4b-BG]
Meter=Shape
Shape=Rectangle 250,440,40,15,3 | Fill Color 0,0,0
Hidden=#Drive5HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4b-Field "ExecuteBatch 1-2"]
[Input4c-BG]
Meter=Shape
Shape=Rectangle 300,440,80,15,3 | Fill Color 0,0,0
Hidden=#Drive5HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4c-Field "ExecuteBatch 1-2"]

[Input4a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=441
Text=#Drive5-Temp_ID#
Hidden=#Drive5HideHWiNFO#
[Input4b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#Drive5-Temp_Instance#
Hidden=#Drive5HideHWiNFO#
[Input4c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#Drive5-Temp_EntryID#
Hidden=#Drive5HideHWiNFO#

[Input4a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=441
W=75
H=13
FocusDismiss=0
DefaultValue=#Drive5-Temp_ID#
Command1=[!SetVariable Drive5-Temp_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-Temp_ID [Input4a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input4b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=441
W=35
H=13
FocusDismiss=0
DefaultValue=#Drive5-Temp_Instance#
Command1=[!SetVariable Drive5-Temp_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-Temp_Instance [Input4b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input4c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=441
W=75
H=13
FocusDismiss=0
DefaultValue=#Drive5-Temp_EntryID#
Command1=[!SetVariable Drive5-Temp_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-Temp_EntryID [Input4c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]


[Input5-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=461
Text="Drive5 Total Activity"
Hidden=#Drive5HideHWiNFO#

[Input5a-BG]
Meter=Shape
Shape=Rectangle 160,460,80,15,3 | Fill Color 0,0,0
Hidden=#Drive5HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5a-Field "ExecuteBatch 1-2"]
[Input5b-BG]
Meter=Shape
Shape=Rectangle 250,460,40,15,3 | Fill Color 0,0,0
Hidden=#Drive5HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5b-Field "ExecuteBatch 1-2"]
[Input5c-BG]
Meter=Shape
Shape=Rectangle 300,460,80,15,3 | Fill Color 0,0,0
Hidden=#Drive5HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5c-Field "ExecuteBatch 1-2"]

[Input5a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=461
Text=#Drive5-TotalActivity_ID#
Hidden=#Drive5HideHWiNFO#
[Input5b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#Drive5-TotalActivity_Instance#
Hidden=#Drive5HideHWiNFO#
[Input5c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#Drive5-TotalActivity_EntryID#
Hidden=#Drive5HideHWiNFO#

[Input5a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=461
W=75
H=13
FocusDismiss=0
DefaultValue=#Drive5-TotalActivity_ID#
Command1=[!SetVariable Drive5-TotalActivity_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-TotalActivity_ID [Input5a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input5b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=461
W=35
H=13
FocusDismiss=0
DefaultValue=#Drive5-TotalActivity_Instance#
Command1=[!SetVariable Drive5-TotalActivity_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-TotalActivity_Instance [Input5b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input5c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=461
W=75
H=13
FocusDismiss=0
DefaultValue=#Drive5-TotalActivity_EntryID#
Command1=[!SetVariable Drive5-TotalActivity_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-TotalActivity_EntryID [Input5c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]


[Input6-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=481
Text="Drive5 Read Rate"
Hidden=#Drive5HideHWiNFO#

[Input6a-BG]
Meter=Shape
Shape=Rectangle 160,480,80,15,3 | Fill Color 0,0,0
Hidden=#Drive5HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6a-Field "ExecuteBatch 1-2"]
[Input6b-BG]
Meter=Shape
Shape=Rectangle 250,480,40,15,3 | Fill Color 0,0,0
Hidden=#Drive5HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6b-Field "ExecuteBatch 1-2"]
[Input6c-BG]
Meter=Shape
Shape=Rectangle 300,480,80,15,3 | Fill Color 0,0,0
Hidden=#Drive5HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6c-Field "ExecuteBatch 1-2"]

[Input6a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=481
Text=#Drive5-ReadRate_ID#
Hidden=#Drive5HideHWiNFO#
[Input6b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#Drive5-ReadRate_Instance#
Hidden=#Drive5HideHWiNFO#
[Input6c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#Drive5-ReadRate_EntryID#
Hidden=#Drive5HideHWiNFO#

[Input6a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=481
W=75
H=13
FocusDismiss=0
DefaultValue=#Drive5-ReadRate_ID#
Command1=[!SetVariable Drive5-ReadRate_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-ReadRate_ID [Input6a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input6b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=481
W=35
H=13
FocusDismiss=0
DefaultValue=#Drive5-ReadRate_Instance#
Command1=[!SetVariable Drive5-ReadRate_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-ReadRate_Instance [Input6b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input6c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=481
W=75
H=13
FocusDismiss=0
DefaultValue=#Drive5-ReadRate_EntryID#
Command1=[!SetVariable Drive5-ReadRate_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-ReadRate_EntryID [Input6c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]


[Input7-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=501
Text="Drive5 Write Rate"
Hidden=#Drive5HideHWiNFO#

[Input7a-BG]
Meter=Shape
Shape=Rectangle 160,500,80,15,3 | Fill Color 0,0,0
Hidden=#Drive5HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7a-Field "ExecuteBatch 1-2"]
[Input7b-BG]
Meter=Shape
Shape=Rectangle 250,500,40,15,3 | Fill Color 0,0,0
Hidden=#Drive5HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7b-Field "ExecuteBatch 1-2"]
[Input7c-BG]
Meter=Shape
Shape=Rectangle 300,500,80,15,3 | Fill Color 0,0,0
Hidden=#Drive5HideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7c-Field "ExecuteBatch 1-2"]

[Input7a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=501
Text=#Drive5-WriteRate_ID#
Hidden=#Drive5HideHWiNFO#
[Input7b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#Drive5-WriteRate_Instance#
Hidden=#Drive5HideHWiNFO#
[Input7c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#Drive5-WriteRate_EntryID#
Hidden=#Drive5HideHWiNFO#

[Input7a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=501
W=75
H=13
FocusDismiss=0
DefaultValue=#Drive5-WriteRate_ID#
Command1=[!SetVariable Drive5-WriteRate_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-WriteRate_ID [Input7a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input7b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=501
W=35
H=13
FocusDismiss=0
DefaultValue=#Drive5-WriteRate_Instance#
Command1=[!SetVariable Drive5-WriteRate_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-WriteRate_Instance [Input7b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]
[Input7c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=501
W=75
H=13
FocusDismiss=0
DefaultValue=#Drive5-WriteRate_EntryID#
Command1=[!SetVariable Drive5-WriteRate_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables Drive5-WriteRate_EntryID [Input7c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh "#ROOTCONFIG#\Panels\Drive5"][!Update]


;---- Special Options ----

[HWiNFO-Divider3]
Meter=Shape
Shape=Rectangle 12,530,375,2,0 | Fill Color 160,160,160
Group=HWiNFO
Hidden=#Drive5HideHWiNFO#

[HWiNFO-SO-Headline]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=25
Y=535
Text="Special Options"
Hidden=#Drive5HideHWiNFO#

[SOption1On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=555
LeftMouseUpAction=[!WriteKeyValue Variables Drive5ShowUsageinLeftRL 0 "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]
Hidden=#Drive5HideHWiNFO#

[SOption1Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=555
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables Drive5ShowUsageinLeftRL 1 "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]
Hidden=#Drive5HideHWiNFO#

[SOption1_Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=15r
Y=0r
Text=#VarShowDriveUsageLeft#
Hidden=#Drive5HideHWiNFO#

[SOption2On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=580
LeftMouseUpAction=[!WriteKeyValue Variables Drive5ShowUsageinRightRL 0 "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]
Hidden=#Drive5HideHWiNFO#

[SOption2Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=580
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables Drive5ShowUsageinRightRL 1 "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\Drive5"][!Refresh]
Hidden=#Drive5HideHWiNFO#

[SOption2_Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=15r
Y=0r
Text=#VarShowDriveUsageRight#
Hidden=#Drive5HideHWiNFO#

;---- Special Options Display ---- 
[SO_Measure]
Measure=Calc
Formula=#Drive5ShowUsageinLeftRL#+#Drive5ShowUsageinRightRL#
IfCondition=(#Drive5ShowUsageinLeftRL# = 1)
IfTrueAction=[!SetOption "LeftRL-Text" "Text" "----- #VarLeftRL# ------#CRLF#Name: Disk Usage"][!SetOption "Input1a-Text" "Text" "-"][!SetOption "Input1b-Text" "Text" "-"][!SetOption "Input1c-Text" "Text" "-"][!SetOption "Input1d-Text" "Text" "-"][!SetOption "Input1e-Text" "Text" "-"][!HideMeter SOption1Off]
IfCondition2=(#Drive5ShowUsageinRightRL# = 1)
IfTrueAction2=[!SetOption "RightRL-Text" "Text" "----- #VarRightRL# ------#CRLF#Name: Disk Usage"][!SetOption "Input2a-Text" "Text" "-"][!SetOption "Input2b-Text" "Text" "-"][!SetOption "Input2c-Text" "Text" "-"][!SetOption "Input2d-Text" "Text" "-"][!SetOption "Input2e-Text" "Text" "-"][!HideMeter SOption2Off]

;---- HWiNFO SM Viewer ----

[HWiNFOSMV]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn350x25.png
X=25	
Y=700
LeftMouseUpAction=["#@#Tools\HWiNFOSharedMemoryViewer.exe]
Hidden=#Drive5HideHWiNFO#
[HWiNFOSMVText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
StringAlign=Center
X=200
Text="Open HWiNFO Shared Memory Viewer"
Hidden=#Drive5HideHWiNFO#



