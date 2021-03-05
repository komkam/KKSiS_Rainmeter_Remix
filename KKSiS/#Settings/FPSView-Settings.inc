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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\FPSView" "FPSView.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\FPSView" "FPSView.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-FPSViewSize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-FPSViewSize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-FPSViewSize" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"]
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
ButtonImage=#@#Images\Buttons\Hide#FPSViewHideRLLabel#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FPSViewHideRLLabel" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#FPSViewHideRLLabel#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FPSViewHideRLLabel" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh]

[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#FPSViewColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FPSViewColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#FPSViewColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FPSViewColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarAVGFPS#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#FPSViewHideAVGFPS#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FPSViewHideAVGFPS" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#FPSViewHideAVGFPS#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FPSViewHideAVGFPS" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh]

[ButtonDescription34]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarFRMTimes#
X=235
Y=20r
[Button34a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#FPSViewHideFrametimes#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FPSViewHideFrametimes" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh]
[Button34b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#FPSViewHideFrametimes#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FPSViewHideFrametimes" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh]

[ButtonDescription35]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarFPSDisplayRes#
X=235
Y=20r
[Button35a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#FPSViewHideDisplayRes#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FPSViewHideDisplayRes" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh]
[Button35b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#FPSViewHideDisplayRes#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "FPSViewHideDisplayRes" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh]

[PrimaryDisplay]
Meter=String
MeterStyle=SettingsStyle-Text
X=235
Y=20r
Text=#VarPrimaryDisplay#
[PrimaryDisplay-BG]
Meter=Shape
Shape=Rectangle 352,165,32,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure PrimaryDisplay-Field "ExecuteBatch 1-2"]
[PrimaryDisplay-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=360
Y=166
Text=#FPSViewDisplayID#
[PrimaryDisplay-Field]
Measure=Plugin
Plugin=InputText
X=354
Y=166
W=28
H=13
FocusDismiss=0
DefaultValue=#FPSViewDisplayID#
Command1=[!SetVariable FPSViewDisplayID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables FPSViewDisplayID [PrimaryDisplay-Field] "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Update]

[MaxFPSCount]
Meter=String
MeterStyle=SettingsStyle-Text
X=235
Y=20r
Text=#VarMaxFPSCount#
[MaxFPSCount-BG]
Meter=Shape
Shape=Rectangle 352,185,32,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure MaxFPSCount-Field "ExecuteBatch 1-2"]
[MaxFPSCount-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=355
Y=186
ToolTipText=#VarCapitalLetter#
Text=#FPSViewMaxFPS#
[MaxFPSCount-Field]
Measure=Plugin
Plugin=InputText
X=354
Y=186
W=28
H=13
FocusDismiss=0
DefaultValue=#FPSViewMaxFPS#
Command1=[!SetVariable FPSViewMaxFPS "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables FPSViewMaxFPS [MaxFPSCount-Field] "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Update]


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
LeftMouseUpAction=[!WriteKeyValue Variables "FPSViewFormat" "HWiNFO" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Refresh "#ROOTCONFIG#\Circles\FPSView"]

[Technology1Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=45r
Y=6r
Text=HWiNFO

[Technology2Btn]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn90x25.png
X=55r
Y=170
LeftMouseUpAction=[!WriteKeyValue Variables "FPSViewFormat" "MSIAB" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Refresh "#ROOTCONFIG#\Circles\FPSView"]

[Technology2Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=45r
Y=6r
Text=MSIAB


;-- Utility Detection -------------------------------------------------------------------------------- 

[Utility-BG1]
Meter=Shape
Shape=Rectangle 10,215,380,520,3 | Fill Color 50,50,50

[Utility-Text]
Meter=String
MeterStyle=SettingsStyle-Text
Y=220
Text=HWiNFO#CRLF#MSI AfterBurner#CRLF#RivaTuner Statistics Server

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
Y=235
X=380
Text=%1

[RTSS_Status]
Measure=Plugin
Plugin=Process
ProcessName=RTSS.exe
RegExpSubstitute=1
Substitute="-1":"not running","1":"running"
IfCondition=(RTSS_Status = 1)
IfTrueAction=[!SetOption RTSS_StatusText FontColor "0,255,0"]
IfFalseAction=[!SetOption RTSS_StatusText FontColor "255,0,0"]

[RTSS_StatusText]
Meter=String
MeterStyle=SettingsStyle-Text
MeasureName=RTSS_Status
StringAlign=Right
Y=250
X=380
Text=%1


;-- Configuration -------------------------------------------------------------------------------- 

[Config-Divider1]
Meter=Shape
Shape=Rectangle 12,270,375,2,0 | Fill Color 160,160,160


[HWiNFO-Sensor-Headline]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Right
X=360
Y=280
Text="Sensor ID        Instance         Entry ID"

[HWiNFORTSS-Text]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=301
Text="HWiNFO RTSS FPS Sensor"

[HWiNFORTSSa-BG]
Meter=Shape
Shape=Rectangle 160,300,80,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure HWiNFORTSSa-Field "ExecuteBatch 1-2"]
[HWiNFORTSSb-BG]
Meter=Shape
Shape=Rectangle 250,300,40,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure HWiNFORTSSb-Field "ExecuteBatch 1-2"]
[HWiNFORTSSc-BG]
Meter=Shape
Shape=Rectangle 300,300,80,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure HWiNFORTSSc-Field "ExecuteBatch 1-2"]

[HWiNFORTSSa-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=301
Text=#GPU-FPS_ID#
[HWiNFORTSSb-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=90r
Y=0r
Text=#GPU-FPS_Instance#
[HWiNFORTSSc-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=50r
Y=0r
Text=#GPU-FPS_EntryID#

[HWiNFORTSSa-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=301
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-FPS_ID#
Command1=[!SetVariable GPU-FPS_ID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-FPS_ID [Input4a-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Update]
[HWiNFORTSSb-Field]
Measure=Plugin
Plugin=InputText
X=251
Y=301
W=35
H=13
FocusDismiss=0
DefaultValue=#GPU-FPS_Instance#
Command1=[!SetVariable GPU-FPS_Instance "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-FPS_Instance [Input4b-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Update]
[HWiNFORTSSc-Field]
Measure=Plugin
Plugin=InputText
X=301
Y=301
W=75
H=13
FocusDismiss=0
DefaultValue=#GPU-FPS_EntryID#
Command1=[!SetVariable GPU-FPS_EntryID "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables GPU-FPS_EntryID [Input4c-Field] "#@#HWiNFO-Sensors.inc"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Update]


[Config-Divider2]
Meter=Shape
Shape=Rectangle 12,325,375,2,0 | Fill Color 160,160,160

[Title-Input]
Meter=String
MeterStyle=SettingsStyle-Text
FontSize=8
X=25
Y=336
Text="FPSView Name"

[Title-BG]
Meter=Shape
Shape=Rectangle 160,335,80,15,3 | Fill Color 0,0,0
LeftMouseUpAction=[!CommandMeasure Title-Field "ExecuteBatch 1-2"]
[Title-Text]
Meter=String
MeterStyle=SettingsStyle-Text
X=165
Y=336
Text=#FPSViewName#
[Title-Field]
Measure=Plugin
Plugin=InputText
X=161
Y=336
W=75
H=13
FocusDismiss=0
DefaultValue=#FPSViewName#
Command1=[!SetVariable FPSViewName "$UserInput$"][!Redraw]
Command2=[!WriteKeyValue Variables FPSViewName [Title-Field] "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Circles\FPSView"][!Refresh "#ROOTCONFIG#\Panels\FPSView"][!Update]

;---- HWiNFO SM Viewer ----

[HWiNFOSMV]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn350x25.png
X=25	
Y=700
LeftMouseUpAction=["#@#Tools\HWiNFOSharedMemoryViewer.exe]
[HWiNFOSMVText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
StringAlign=Center
X=200
Text="Open HWiNFO Shared Memory Viewer"




