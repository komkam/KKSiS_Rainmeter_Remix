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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\WiFi" "WiFi.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\WiFi" "WiFi.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-WiFiSize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-WiFiSize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"]
[Button2bText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarSquare#


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

[ButtonDescription3a]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarHideWiFiQuality#
X=235
Y=65
[Button31a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#WiFiHideQuality#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "WiFiHideQuality" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#WiFiHideQuality#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "WiFiHideQuality" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]

[ButtonDescription3b]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarHideWiFiSSID#
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#WiFiHideSSID#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "WiFiHideSSID" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#WiFiHideSSID#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "WiFiHideSSID" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]

[ButtonDescription3c]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarIcons#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#WiFiColoredIcons#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "WiFiColoredIcons" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#WiFiColoredIcons#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "WiFiColoredIcons" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]



;---- Interface Selection ----

[Selection-BG1]
Meter=Shape
Shape=Rectangle 10,140,380,595,3 | Fill Color 50,50,50
Group=HWiNFO

[Selection-Divider]
Meter=Shape
Shape=Rectangle 12,160,375,2,0 | Fill Color 160,160,160

[Selection-Headline]
Meter=String
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=25
Y=145
Text="WiFi Interface"


[Measure_Option1]
Measure=Plugin
Plugin=UsageMonitor
Category=Network Adapter
Counter=Current Bandwidth
Index=0
[SOption1On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=170
[SOption1Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=170
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables WiFiAdapterIndex "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]
[SOption1_Text]
Meter=String
MeasureName=Measure_Option2
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=[Measure_Option1]
Clipstring=1
W=340

[Measure_Option2]
Measure=Plugin
Plugin=UsageMonitor
Category=Network Adapter
Counter=Current Bandwidth
Index=1
[SOption2On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=190
[SOption2Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=190
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables WiFiAdapterIndex "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]
[SOption2_Text]
Meter=String
MeasureName=Measure_Option2
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=[Measure_Option2]
Clipstring=1
W=340

[Measure_Option3]
Measure=Plugin
Plugin=UsageMonitor
Category=Network Adapter
Counter=Current Bandwidth
Index=2
[SOption3On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=210
[SOption3Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=210
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables WiFiAdapterIndex "2" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]
[SOption3_Text]
Meter=String
MeasureName=Measure_Option2
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=[Measure_Option3]
Clipstring=1
W=340

[Measure_Option4]
Measure=Plugin
Plugin=UsageMonitor
Category=Network Adapter
Counter=Current Bandwidth
Index=3
[SOption4On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=230
[SOption4Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=230
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables WiFiAdapterIndex "3" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]
[SOption4_Text]
Meter=String
MeasureName=Measure_Option2
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=[Measure_Option4]
Clipstring=1
W=340

[Measure_Option5]
Measure=Plugin
Plugin=UsageMonitor
Category=Network Adapter
Counter=Current Bandwidth
Index=4
[SOption5On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=250
[SOption5Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=250
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables WiFiAdapterIndex "4" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]
[SOption5_Text]
Meter=String
MeasureName=Measure_Option2
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=[Measure_Option5]
Clipstring=1
W=340

[Measure_Option6]
Measure=Plugin
Plugin=UsageMonitor
Category=Network Adapter
Counter=Current Bandwidth
Index=5
[SOption6On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=270
[SOption6Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=270
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables WiFiAdapterIndex "5" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]
[SOption6_Text]
Meter=String
MeasureName=Measure_Option2
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=[Measure_Option6]
Clipstring=1
W=340

[Measure_Option7]
Measure=Plugin
Plugin=UsageMonitor
Category=Network Adapter
Counter=Current Bandwidth
Index=6
[SOption7On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=290
[SOption7Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=290
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables WiFiAdapterIndex "6" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]
[SOption7_Text]
Meter=String
MeasureName=Measure_Option2
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=[Measure_Option7]
Clipstring=1
W=340

[Measure_Option8]
Measure=Plugin
Plugin=UsageMonitor
Category=Network Adapter
Counter=Current Bandwidth
Index=7
[SOption8On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=310
[SOption8Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=310
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables WiFiAdapterIndex "7" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]
[SOption8_Text]
Meter=String
MeasureName=Measure_Option2
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=[Measure_Option8]
Clipstring=1
W=340

[Measure_Option9]
Measure=Plugin
Plugin=UsageMonitor
Category=Network Adapter
Counter=Current Bandwidth
Index=8
[SOption9On]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox1.png
X=25	
Y=330
[SOption9Off]
Meter=Button
ButtonImage=#@#Images\Buttons\Checkbox0.png
X=25	
Y=330
DynamicVariables=1
LeftMouseUpAction=[!WriteKeyValue Variables WiFiAdapterIndex "8" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\WiFi"][!Refresh "#ROOTCONFIG#\Circles\WiFi"][!Refresh]
[SOption9_Text]
Meter=String
MeasureName=Measure_Option2
MeterStyle=SettingsStyle-Text
StringAlign=Left
X=20r
Y=0r
Text=[Measure_Option9]
Clipstring=1
W=340


;---- Selection ---- 
[SO_Measure]
Measure=Calc
Formula=#WiFiAdapterIndex#
IfCondition=(#WiFiAdapterIndex# = 0)
IfTrueAction=[!HideMeter SOption1Off]
IfCondition2=(#WiFiAdapterIndex# = 1)
IfTrueAction2=[!HideMeter SOption2Off]
IfCondition3=(#WiFiAdapterIndex# = 2)
IfTrueAction3=[!HideMeter SOption3Off]
IfCondition4=(#WiFiAdapterIndex# = 3)
IfTrueAction4=[!HideMeter SOption4Off]
IfCondition5=(#WiFiAdapterIndex# = 4)
IfTrueAction5=[!HideMeter SOption5Off]
IfCondition6=(#WiFiAdapterIndex# = 5)
IfTrueAction6=[!HideMeter SOption6Off]
IfCondition7=(#WiFiAdapterIndex# = 6)
IfTrueAction7=[!HideMeter SOption7Off]
IfCondition8=(#WiFiAdapterIndex# = 7)
IfTrueAction8=[!HideMeter SOption8Off]
IfCondition9=(#WiFiAdapterIndex# = 8)
IfTrueAction9=[!HideMeter SOption9Off]
