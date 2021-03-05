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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\Network" "Network.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\Network" "Network.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-NetworkSize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-NetworkSize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-NetworkSize" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"]
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
Text=#VarRoundlineName# Label
X=235
Y=65
[Button31a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#NetworkHideRLLabel#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "NetworkHideRLLabel" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#NetworkHideRLLabel#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "NetworkHideRLLabel" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]

[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#NetworkColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "NetworkColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#NetworkColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "NetworkColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=Windows1 Graph
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#NetworkHideGraph1#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "NetworkHideGraph1" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#NetworkHideGraph1#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "NetworkHideGraph1" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]

[ButtonDescription34]
Meter=String
MeterStyle=SettingsStyle-Text
Text=Windows2 Graph
X=235
Y=20r
[Button34a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#NetworkHideGraph2#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "NetworkHideGraph2" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[Button34b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#NetworkHideGraph2#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "NetworkHideGraph2" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]

[ButtonDescription35]
Meter=String
MeterStyle=SettingsStyle-Text
Text=Panel Bar
X=235
Y=20r
[Button35a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#NetworkHideBar#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "NetworkHideBar" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[Button35b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#NetworkHideBar#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "NetworkHideBar" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]


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
ButtonImage=#@#Images\Buttons\Btn90x25.png
X=20
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "NetworkFormat" "Windows" "#@#Variables.inc"][!WriteKeyValue Variables "NetworkFormat3" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]

[Technology1Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=45r
Y=6r
Text=Windows 1

[Technology2Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn90x25.png
X=55r
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "NetworkFormat" "Windows" "#@#Variables.inc"][!WriteKeyValue Variables "NetworkFormat3" "2" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]

[Technology2Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=45r
Y=6r
Text=Windows 2


;---- Configuration ---

[Config-BG1]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50

[Config-Text1]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=Config

[Config-Divider1]
Meter=Shape
Shape=Rectangle 12,235,375,2,0 | Fill Color 160,160,160

[Config_Image]
Meter=Image
ImageName=#@#Images\General\Windows-Network.png
X=135
Y=265
W=125



;---- Left Roundline ----

[LeftRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=240
Text=----- #VarLeftRL# ------#CRLF#Name: LAN IN

[Input1-BG]
Meter=Shape
Shape=Rectangle 15,280,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input1-Field "ExecuteBatch 1-2"]

[Input1-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=281
Text=Bandwidth: #LANMaxInValueInMBits#
ToolTipText=Example:#CRLF#Enter 2500 for 2.5GbE Port#CRLF#Enter 1000 for 1GbE Port#CRLF#Enter 100 for DSL 100Mbit

[Input1-Text2]
Meter=String
MeterStyle=SettingsStyle-Text
X=16
Y=300
Text=(in Mbits/s)

[Input1-Field]
Measure=Plugin
Plugin=InputText
X=16
Y=281
W=115
H=13
FocusDismiss=0
DefaultValue=#LANMaxInValueInMBits#
Command1=[!SetVariable LANMaxInValueInMBits "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables LANMaxInValueInMBits [Input1-Field] "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Update]


;---- Right Roundline ----

[RightRL-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=380
Y=240
Text=------ #VarRightRL# ------#CRLF#Name: LAN OUT

[Input2-BG]
Meter=Shape
Shape=Rectangle 260,280,120,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input2-Field "ExecuteBatch 1-2"]

[Input2-Text]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=281
Text=Bandwidth: #LANMaxOutValueInMBits#
ToolTipText=Example:#CRLF#Enter 2500 for 2.5GbE Port#CRLF#Enter 1000 for 1GbE Port#CRLF#Enter 100 for DSL 100Mbit

[Input2-Text2]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=379
Y=301
Text=(in Mbits/s)

[Input2-Field]
Measure=Plugin
Plugin=InputText
X=261
Y=281
W=115
H=13
FocusDismiss=0
DefaultValue=#LANMaxOutValueInMBits#
Command1=[!SetVariable LANMaxOutValueInMBits "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables LANMaxOutValueInMBits [Input2-Field] "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Update]


;---- Title ----

[Input3-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=Config_Measure_RightRL_Name
X=145
Y=386
Text=Network Name:

[Input3-Info]
Meter=String
MeterStyle=SettingsStyle-Text
X=255
Y=386
Text=(%1 = AutoDetect)

[Input3-BG]
Meter=Shape
Shape=Rectangle 150,385,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input3-Field "ExecuteBatch 1-2"]

[Input3-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=386
Text=#LANNameWin#

[Input3-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=386
W=95
H=13
FocusDismiss=0
DefaultValue=#LANNameWin#
Command1=[!SetVariable LANNameWin "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables LANNameWin [Input3-Field] "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Update]


[Input4-Description]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
MeasureName=Config_Measure_RightRL_Name
X=145
Y=406
Text=Custom Name Filter:

[Input4-BG]
Meter=Shape
Shape=Rectangle 150,405,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input4-Field "ExecuteBatch 1-2"]

[Input4-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=151
Y=406
Text=#LANCustomSubstitute#
ToolTipText=#CRLF#Enter the word(s) or sign(s) you would like to hide#CRLF#By default "(R)", "Gigabit", "Network" and "Connection" are hidden 

[Input4-Field]
Measure=Plugin
Plugin=InputText
X=151
Y=406
W=95
H=13
FocusDismiss=0
DefaultValue=#LANCustomSubstitute#
Command1=[!SetVariable LANCustomSubstitute "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables LANCustomSubstitute [Input4-Field] "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Update]

[Input4b-BG]
Meter=Shape
Shape=Rectangle 260,405,100,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Input4b-Field "ExecuteBatch 1-2"]

[Input4b-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=261
Y=406
Text=#LANCustomSubstitute2#
ToolTipText=#CRLF#Enter the word(s) or sign(s) you would like to hide#CRLF#By default "(R)", "Gigabit", "Network" and "Connection" are hidden 

[Input4b-Field]
Measure=Plugin
Plugin=InputText
X=261
Y=406
W=95
H=13
FocusDismiss=0
DefaultValue=#LANCustomSubstitute2#
Command1=[!SetVariable LANCustomSubstitute2 "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables LANCustomSubstitute2 [Input4b-Field] "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Update]


;---- Interface Selection ----

[Selection-Divider]
Meter=Shape
Shape=Rectangle 12,430,375,2,0 | Fill Color 160,160,160

[Selection-Headline]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=25
Y=435
Text="Interface"

[Measure_Option1]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=ADAPTER_DESCRIPTION
SysInfoData		=Best
DynamicVariables=1
[SOption1Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=455
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables LANInterface "Best" "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[SOption1On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=455
[SOption1_Text]
Meter=String
MeasureName=Measure_Option1
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=Auto Detected: %1
Clipstring=1
W=340

[Measure_Option2]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=ADAPTER_DESCRIPTION
SysInfoData		=0
DynamicVariables=1
[SOption2On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=480
[SOption2Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=480
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables LANInterface "0" "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[SOption2_Text]
Meter=String
MeasureName=Measure_Option2
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=Interface0: %1
Clipstring=1
W=340

[Measure_Option3]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=ADAPTER_DESCRIPTION
SysInfoData		=1
DynamicVariables=1
[SOption3On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=500
[SOption3Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=500
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables LANInterface "1" "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[SOption3_Text]
Meter=String
MeasureName=Measure_Option3
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=Interface1: %1
Clipstring=1
W=340

[Measure_Option4]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=ADAPTER_DESCRIPTION
SysInfoData		=2
DynamicVariables=1
[SOption4On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=520
[SOption4Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=520
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables LANInterface "2" "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[SOption4_Text]
Meter=String
MeasureName=Measure_Option4
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=Interface2: %1
Clipstring=1
W=340

[Measure_Option5]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=ADAPTER_DESCRIPTION
SysInfoData		=3
DynamicVariables=1
[SOption5On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=540
[SOption5Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=540
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables LANInterface "3" "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[SOption5_Text]
Meter=String
MeasureName=Measure_Option5
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=Interface3: %1
Clipstring=1
W=340

[Measure_Option6]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=ADAPTER_DESCRIPTION
SysInfoData		=4
DynamicVariables=1
[SOption6On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=560
[SOption6Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=560
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables LANInterface "4" "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[SOption6_Text]
Meter=String
MeasureName=Measure_Option5
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=Interface4: %1
Clipstring=1
W=340

[Measure_Option7]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=ADAPTER_DESCRIPTION
SysInfoData		=5
DynamicVariables=1
[SOption7On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=580
[SOption7Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=580
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables LANInterface "5" "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[SOption7_Text]
Meter=String
MeasureName=Measure_Option5
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=Interface5: %1
Clipstring=1
W=340

[Measure_Option8]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=ADAPTER_DESCRIPTION
SysInfoData		=6
DynamicVariables=1
[SOption8On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=600
[SOption8Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=600
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables LANInterface "6" "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[SOption8_Text]
Meter=String
MeasureName=Measure_Option5
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=Interface6: %1
Clipstring=1
W=340

[Measure_Option9]
Measure			=Plugin
Plugin			=SysInfo
SysInfoType		=ADAPTER_DESCRIPTION
SysInfoData		=7
DynamicVariables=1
[SOption9On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=620
[SOption9Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=620
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables LANInterface "7" "#@#Windows-Sensors.inc"][!Refresh "#ROOTCONFIG#\Panels\Network"][!Refresh "#ROOTCONFIG#\Circles\Network"][!Refresh]
[SOption9_Text]
Meter=String
MeasureName=Measure_Option5
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=Interface7: %1
Clipstring=1
W=340

;---- Selection ---- 
[SO_Measure]
Measure=Calc
Formula=#LANInterface#
IfCondition=(#LANInterface# = 0)
IfTrueAction=[!HideMeter SOption2Off][!HideMeter SOption1On]
IfCondition2=(#LANInterface# = 1)
IfTrueAction2=[!HideMeter SOption3Off][!HideMeter SOption1On]
IfCondition3=(#LANInterface# = 2)
IfTrueAction3=[!HideMeter SOption4Off][!HideMeter SOption1On]
IfCondition4=(#LANInterface# = 3)
IfTrueAction4=[!HideMeter SOption5Off][!HideMeter SOption1On]
IfCondition5=(#LANInterface# = 4)
IfTrueAction5=[!HideMeter SOption6Off][!HideMeter SOption1On]
IfCondition6=(#LANInterface# = 5)
IfTrueAction6=[!HideMeter SOption7Off][!HideMeter SOption1On]
IfCondition7=(#LANInterface# = 6)
IfTrueAction7=[!HideMeter SOption8Off][!HideMeter SOption1On]
IfCondition8=(#LANInterface# = 7)
IfTrueAction8=[!HideMeter SOption9Off][!HideMeter SOption1On]

