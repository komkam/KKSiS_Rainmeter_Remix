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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\RAM" "RAM.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\RAM" "RAM.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-RAMSize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-RAMSize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-RAMSize" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"]
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
ButtonImage=#@#Images\Buttons\Hide#RAMHideGraph#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMHideGraph" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#RAMHideGraph#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMHideGraph" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]

[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarRoundlineName# Label
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#RAMHideRLLabel#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMHideRLLabel" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#RAMHideRLLabel#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMHideRLLabel" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#RAMColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#RAMColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]

[ButtonDescription34]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarShowPercent#
X=235
Y=20r
[Button34a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#RAMShowPercentage#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMShowPercentage" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]
[Button34b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#RAMShowPercentage#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMShowPercentage" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]

[ButtonDescription35]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarShowFreeSpace#
X=235
Y=20r
[Button35a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#RAMShowFreeSpace#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMShowFreeSpace" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]
[Button35b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#RAMShowFreeSpace#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMShowFreeSpace" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]

[ButtonDescription36]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarShowRamOnly#
X=235
Y=20r
[Button36a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#RAMShowRAMonly#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMShowRAMonly" "0" "#@#Variables.inc"][!WriteKeyValue Variables "RAMShowTemp" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]
[Button36b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#RAMShowRAMonly#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMShowRAMonly" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]

[ButtonDescription37]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarShowRamTemp#
X=235
Y=20r
Group=Button37
[Button37a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#RAMShowTemp#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMShowTemp" "1" "#@#Variables.inc"][!WriteKeyValue Variables "RAMShowRAMonly" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh]
Group=Button37
[Button37b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#RAMShowTemp#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "RAMShowTemp" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh]
Group=Button37
[Button37bOnOff]
Measure=String
String=#RAMFormat#
IfMatch=Windows
IfMatchAction=[!HideMeterGroup Button37]
IfNotMatchAction=[!ShowMeterGroup Button37]


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
LeftMouseUpAction=[!WriteKeyValue Variables "RAMFormat" "Windows" "#@#Variables.inc"][!WriteKeyValue Variables "RAMFormat2" "" "#@#Variables.inc"][!WriteKeyValue Variables "RAMHideWindows" "0" "#@#Variables.inc"][!WriteKeyValue Variables "RAMHideHWiNFO" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]

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
LeftMouseUpAction=[!WriteKeyValue Variables "RAMFormat" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "RAMFormat2" "" "#@#Variables.inc"][!WriteKeyValue Variables "RAMHideWindows" "1" "#@#Variables.inc"][!WriteKeyValue Variables "RAMHideHWiNFO" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]

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
LeftMouseUpAction=[!WriteKeyValue Variables "RAMFormat" "HWiNFO" "#@#Variables.inc"][!WriteKeyValue Variables "RAMFormat2" "2" "#@#Variables.inc"][!WriteKeyValue Variables "RAMHideWindows" "1" "#@#Variables.inc"][!WriteKeyValue Variables "RAMHideHWiNFO" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh]

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
Hidden=#RAMHideWindows#

[Windows-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=Windows
Group=Windows
Hidden=#RAMHideWindows#

[Windows-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160
Group=Windows
Hidden=#RAMHideWindows#

[Windows-LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=240
Text=----- #VarLeftRL# ------#CRLF#Name: RAM
Hidden=#RAMHideWindows#

[Windows-RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=380
Y=240
Text=------ #VarRightRL# ------#CRLF#Name: RAM
Hidden=#RAMHideWindows#

[Windows_Image]
Meter=Image
ImageName=#@#Images\General\Windows-RAM.png
X=135
Y=265
W=125
Hidden=#RAMHideWindows#

;---- Title ----

[Windows-Input1-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=145
Y=386
Text=RAM Name:
Hidden=#RAMHideWindows#

[Windows-Input1-BG]
Meter=Shape
Shape=Rectangle 150,385,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Windows-Input1-Field "ExecuteBatch 1-2"]
Hidden=#RAMHideWindows#

[Windows-Input1-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=386
Text=#RAMNameWin#
Hidden=#RAMHideWindows#

[Windows-Input1-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=386
W=95
H=13
FocusDismiss=0
DefaultValue=#RAMNameWin#
Command1=[!SetVariable RAMNameWin "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables RAMNameWin [Windows-Input1-Field] "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]


;-- HWiNFO -------------------------------------------------------------------------------- 

[HWiNFO-BG1]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50
Group=HWiNFO
Hidden=#RAMHideHWiNFO#

[HWiNFO-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=HWiNFO
Group=HWiNFO
Hidden=#RAMHideHWiNFO#

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
Hidden=#RAMHideHWiNFO#

[HWiNFO-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160
Group=HWiNFO
Hidden=#RAMHideHWiNFO#

[HWiNFO_Measure_LeftRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#RAM-LeftRL_Id#
HWiNFOSensorInstance=#RAM-LeftRL_Instance#
HWiNFOEntryId		=#RAM-LeftRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1
Hidden=#RAMHideHWiNFO#


[HWiNFO_Measure_RightRL_Name]
Measure				=Plugin
Plugin				=HWiNFO
HWiNFOSensorId		=#RAM-RightRL_Id#
HWiNFOSensorInstance=#RAM-RightRL_Instance#
HWiNFOEntryId		=#RAM-RightRL_EntryId#
HWiNFOType			=EntryName
UpdateDivider		=1
DynamicVariables	=1
Hidden=#RAMHideHWiNFO#

[HWiNFO_Image]
Meter=Image
ImageName=#@#Images\General\HWiNFO-RAM.png
X=135
Y=265
W=125
Hidden=#RAMHideHWiNFO#


;---- Left Roundline ----

[LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
MeasureName=HWiNFO_Measure_LeftRL_Name
X=15
Y=240
Text=----- #VarLeftRL# ------#CRLF#Name: RAM
Hidden=#RAMHideHWiNFO#


;---- Right Roundline ----

[RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=380
Y=240
Text=------ #VarRightRL# ------#CRLF#Name: Swap
Hidden=#RAMHideHWiNFO#

[MeasureRightRLTemp]
Measure=Calc
Formula=#RAMShowTemp#+#RAMShowRAMonly#
IfCondition=(#RAMShowRAMonly# = 0) && (#RAMShowTemp# = 0)
IfTrueAction=[!SetOption "RightRL-Text" Text "------ #VarRightRL# ------#CRLF#Name: Swap"][!SetOption "Windows-RightRL-Text" Text "------ #VarRightRL# ------#CRLF#Name: Swap"]
IfCondition2=(#RAMShowRAMonly# = 1) && (#RAMShowTemp# = 0)
IfTrueAction2=[!SetOption "RightRL-Text" Text "------ #VarRightRL# ------#CRLF#Name: RAM"][!SetOption "Windows-RightRL-Text" Text "------ #VarRightRL# ------#CRLF#Name: RAM"]
IfCondition3=(#RAMShowRAMonly# = 1) && (#RAMShowTemp# = 1)
IfTrueAction3=[!SetOption "RightRL-Text" Text "------ #VarRightRL# ------#CRLF#Name: Temp"][!SetOption "Windows-RightRL-Text" Text "------ #VarRightRL# ------#CRLF#Name: Swap"]


;---- Title ----

[Input3-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=HWiNFO_Measure_RightRL_Name
X=145
Y=386
Text=RAM Name:
Hidden=#RAMHideHWiNFO#

[Input3-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=386
Text=(%1 = AutoDetect)
Hidden=#RAMHideHWiNFO#

[Input3-BG]
Meter=Shape
Shape=Rectangle 150,385,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input3-Field "ExecuteBatch 1-2"]
Hidden=#RAMHideHWiNFO#

[Input3-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=386
Text=#RAMName#
Hidden=#RAMHideHWiNFO#

[Input3-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=386
W=95
H=13
FocusDismiss=0
DefaultValue=#RAMName#
Command1=[!SetVariable RAMName "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables RAMName [Input3-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]


;---- HWiNFO Sensors

[HWiNFO-Divider2]
Meter=Shape
Shape=Rectangle 12,410,375,2,0 | Fill Color 160,160,160
Group=HWiNFO
Hidden=#RAMHideHWiNFO#

[HWiNFO-Sensor-Headline]
Meter=String
MeterStyle=SettingsStyle-Text
Hidden=#RAMHideHWiNFO#
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
Text=Memory Clock
Hidden=#RAMHideHWiNFO#

[Input4a-BG]
Meter=Shape
Shape=Rectangle 160,440,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4a-Field "ExecuteBatch 1-2"]
[Input4b-BG]
Meter=Shape
Shape=Rectangle 250,440,40,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4b-Field "ExecuteBatch 1-2"]
[Input4c-BG]
Meter=Shape
Shape=Rectangle 300,440,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input4c-Field "ExecuteBatch 1-2"]

[Input4a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=441
Text=#DRAM-Clock_ID#
Hidden=#RAMHideHWiNFO#
[Input4b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#DRAM-Clock_Instance#
Hidden=#RAMHideHWiNFO#
[Input4c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#DRAM-Clock_EntryID#
Hidden=#RAMHideHWiNFO#

[Input4a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=441
W=75
H=13
FocusDismiss=0
DefaultValue=#DRAM-Clock_ID#
Command1=[!SetVariable DRAM-Clock_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-Clock_ID [Input4a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input4b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=441
W=35
H=13
FocusDismiss=0
DefaultValue=#DRAM-Clock_Instance#
Command1=[!SetVariable DRAM-Clock_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-Clock_Instance [Input4b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input4c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=441
W=75
H=13
FocusDismiss=0
DefaultValue=#DRAM-Clock_EntryID#
Command1=[!SetVariable DRAM-Clock_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-Clock_EntryID [Input4c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]


[Input5-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=461
Text=TCAS
Hidden=#RAMHideHWiNFO#

[Input5a-BG]
Meter=Shape
Shape=Rectangle 160,460,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5a-Field "ExecuteBatch 1-2"]
[Input5b-BG]
Meter=Shape
Shape=Rectangle 250,460,40,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5b-Field "ExecuteBatch 1-2"]
[Input5c-BG]
Meter=Shape
Shape=Rectangle 300,460,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input5c-Field "ExecuteBatch 1-2"]

[Input5a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=461
Text=#DRAM-TCAS_ID#
Hidden=#RAMHideHWiNFO#
[Input5b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#DRAM-TCAS_Instance#
Hidden=#RAMHideHWiNFO#
[Input5c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#DRAM-TCAS_EntryID#
Hidden=#RAMHideHWiNFO#

[Input5a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=461
W=75
H=13
FocusDismiss=0
DefaultValue=#DRAM-TCAS_ID#
Command1=[!SetVariable DRAM-TCAS_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TCAS_ID [Input5a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input5b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=461
W=35
H=13
FocusDismiss=0
DefaultValue=#DRAM-TCAS_Instance#
Command1=[!SetVariable DRAM-TCAS_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TCAS_Instance [Input5b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input5c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=461
W=75
H=13
FocusDismiss=0
DefaultValue=#DRAM-TCAS_EntryID#
Command1=[!SetVariable DRAM-TCAS_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TCAS_EntryID [Input5c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]


[Input6-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=481
Text=TRCD
Hidden=#RAMHideHWiNFO#

[Input6a-BG]
Meter=Shape
Shape=Rectangle 160,480,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6a-Field "ExecuteBatch 1-2"]
[Input6b-BG]
Meter=Shape
Shape=Rectangle 250,480,40,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6b-Field "ExecuteBatch 1-2"]
[Input6c-BG]
Meter=Shape
Shape=Rectangle 300,480,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input6c-Field "ExecuteBatch 1-2"]

[Input6a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=481
Text=#DRAM-TRCD_ID#
Hidden=#RAMHideHWiNFO#
[Input6b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#DRAM-TRCD_Instance#
Hidden=#RAMHideHWiNFO#
[Input6c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#DRAM-TRCD_EntryID#
Hidden=#RAMHideHWiNFO#

[Input6a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=481
W=75
H=13
FocusDismiss=0
DefaultValue=#DRAM-TRCD_ID#
Command1=[!SetVariable DRAM-TRCD_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TRCD_ID [Input6a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input6b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=481
W=35
H=13
FocusDismiss=0
DefaultValue=#DRAM-TRCD_Instance#
Command1=[!SetVariable DRAM-TRCD_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TRCD_Instance [Input6b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input6c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=481
W=75
H=13
FocusDismiss=0
DefaultValue=#DRAM-TRCD_EntryID#
Command1=[!SetVariable DRAM-TRCD_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TRCD_EntryID [Input6c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]


[Input7-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=501
Text=TRP
Hidden=#RAMHideHWiNFO#

[Input7a-BG]
Meter=Shape
Shape=Rectangle 160,500,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7a-Field "ExecuteBatch 1-2"]
[Input7b-BG]
Meter=Shape
Shape=Rectangle 250,500,40,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7b-Field "ExecuteBatch 1-2"]
[Input7c-BG]
Meter=Shape
Shape=Rectangle 300,500,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input7c-Field "ExecuteBatch 1-2"]

[Input7a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=501
Text=#DRAM-TRP_ID#
Hidden=#RAMHideHWiNFO#
[Input7b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#DRAM-TRP_Instance#
Hidden=#RAMHideHWiNFO#
[Input7c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#DRAM-TRP_EntryID#
Hidden=#RAMHideHWiNFO#

[Input7a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=501
W=75
H=13
FocusDismiss=0
DefaultValue=DRAM-TRP_ID#
Command1=[!SetVariable DRAM-TRP_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TRP_ID [Input7a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input7b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=501
W=35
H=13
FocusDismiss=0
DefaultValue=#DRAM-TRP_Instance#
Command1=[!SetVariable DRAM-TRP_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TRP_Instance [Input7b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input7c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=501
W=75
H=13
FocusDismiss=0
DefaultValue=#DRAM-TRP_EntryID#
Command1=[!SetVariable DRAM-TRP_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TRP_EntryID [Input7c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]


[Input8-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=521
Text=TRAS
Hidden=#RAMHideHWiNFO#

[Input8a-BG]
Meter=Shape
Shape=Rectangle 160,520,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input8a-Field "ExecuteBatch 1-2"]
[Input8b-BG]
Meter=Shape
Shape=Rectangle 250,520,40,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input8b-Field "ExecuteBatch 1-2"]
[Input8c-BG]
Meter=Shape
Shape=Rectangle 300,520,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input8c-Field "ExecuteBatch 1-2"]

[Input8a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=521
Text=#DRAM-TRAS_ID#
Hidden=#RAMHideHWiNFO#
[Input8b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#DRAM-TRAS_Instance#
Hidden=#RAMHideHWiNFO#
[Input8c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#DRAM-TRAS_EntryID#
Hidden=#RAMHideHWiNFO#

[Input8a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=521
W=75
H=13
FocusDismiss=0
DefaultValue=#DRAM-TRAS_ID#
Command1=[!SetVariable DRAM-TRAS_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TRAS_ID [Input8a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input8b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=521
W=35
H=13
FocusDismiss=0
DefaultValue=#DRAM-TRAS_Instance#
Command1=[!SetVariable DRAM-TRAS_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TRAS_Instance [Input8b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input8c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=521
W=75
H=13
FocusDismiss=0
DefaultValue=#DRAM-TRAS_EntryID#
Command1=[!SetVariable DRAM-TRAS_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TRAS_EntryID [Input8c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]

[Input9-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=541
Text=TRC
Hidden=#RAMHideHWiNFO#

[Input9a-BG]
Meter=Shape
Shape=Rectangle 160,540,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input9a-Field "ExecuteBatch 1-2"]
[Input9b-BG]
Meter=Shape
Shape=Rectangle 250,540,40,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input9b-Field "ExecuteBatch 1-2"]
[Input9c-BG]
Meter=Shape
Shape=Rectangle 300,540,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input9c-Field "ExecuteBatch 1-2"]

[Input9a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=541
Text=#DRAM-TRC_ID#
Hidden=#RAMHideHWiNFO#
[Input9b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#DRAM-TRC_Instance#
Hidden=#RAMHideHWiNFO#
[Input9c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#DRAM-TRC_EntryID#
Hidden=#RAMHideHWiNFO#

[Input9a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=541
W=75
H=13
FocusDismiss=0
DefaultValue=#DRAM-TRC_ID#
Command1=[!SetVariable DRAM-TRC_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TRC_ID [Input9a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input9b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=541
W=35
H=13
FocusDismiss=0
DefaultValue=#DRAM-TRC_Instance#
Command1=[!SetVariable DRAM-TRC_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TRC_Instance [Input9b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input9c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=541
W=75
H=13
FocusDismiss=0
DefaultValue=#DRAM-TRC_EntryID#
Command1=[!SetVariable DRAM-TRC_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-TRC_EntryID [Input9c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]

[Input10-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=561
Text=Temperature
Hidden=#RAMHideHWiNFO#

[Input10a-BG]
Meter=Shape
Shape=Rectangle 160,560,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input10a-Field "ExecuteBatch 1-2"]
[Input10b-BG]
Meter=Shape
Shape=Rectangle 250,560,40,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input10b-Field "ExecuteBatch 1-2"]
[Input10c-BG]
Meter=Shape
Shape=Rectangle 300,560,80,15,3 | Fill Color 0,0,0
Hidden=#RAMHideHWiNFO#
LeftMouseUpAction=[!CommandMeasure Input10c-Field "ExecuteBatch 1-2"]

[Input10a-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=561
Text=#DRAM-Temp_ID#
Hidden=#RAMHideHWiNFO#
[Input10b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#DRAM-Temp_Instance#
Hidden=#RAMHideHWiNFO#
[Input10c-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#DRAM-Temp_EntryID#
Hidden=#RAMHideHWiNFO#

[Input10a-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=561
W=75
H=13
FocusDismiss=0
DefaultValue=#DRAM-Temp_ID#
Command1=[!SetVariable DRAM-Temp_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-Temp_ID [Input10a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input10b-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=561
W=35
H=13
FocusDismiss=0
DefaultValue=#DRAM-Temp_Instance#
Command1=[!SetVariable DRAM-Temp_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-Temp_Instance [Input10b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]
[Input10c-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=561
W=75
H=13
FocusDismiss=0
DefaultValue=#DRAM-Temp_EntryID#
Command1=[!SetVariable DRAM-Temp_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables DRAM-Temp_EntryID [Input10c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\RAM"][!Refresh "#ROOTCONFIG#\Panels\RAM"][!Update]



;-- HWiNFO SM Viewer ---------------------------------------------------------------------------------- 

[HWiNFOSMV]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn350x25.png
X=25	
Y=700
LeftMouseUpAction=["#@#Tools\HWiNFOSharedMemoryViewer.exe]
Hidden=#RAMHideHWiNFO#
[HWiNFOSMVText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
StringAlign=Center
X=200
Text="Open HWiNFO Shared Memory Viewer"
Hidden=#RAMHideHWiNFO#
