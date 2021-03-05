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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Panels\Time" "Time.ini"]

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
ButtonCommand=[!ToggleConfig "#ROOTCONFIG#\Circles\Time" "Time.ini"]

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
ButtonCommand=[!WriteKeyValue Variables "Panel-TISize" "Small" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-TISize" "Mid" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"]
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
ButtonCommand=[!WriteKeyValue Variables "Panel-TISize" "Big" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"]
[Button2cText]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=40r
Y=0r
Text=#VarBig#


;---- Options ----

[Background3]
Meter=Shape
Shape=Rectangle 230,35,160,175,3 | Fill Color 50,50,50

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
Text=#VarColoredFrame#
X=235
Y=65
[Button31a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#TIShowColoredWeekday#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "TIShowColoredWeekday" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"][!Refresh "#ROOTCONFIG#\Circles\Time"][!Refresh]
[Button31b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#TIShowColoredWeekday#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "TIShowColoredWeekday" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"][!Refresh "#ROOTCONFIG#\Circles\Time"][!Refresh]

[ButtonDescription32]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarShowSeconds#
X=235
Y=20r
[Button32a]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#TIHideSeconds#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "TIHideSeconds" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"][!Refresh "#ROOTCONFIG#\Circles\Time"][!Refresh]
[Button32b]
Meter=Button
ButtonImage=#@#Images\Buttons\Hide#TIHideSeconds#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "TIHideSeconds" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"][!Refresh "#ROOTCONFIG#\Circles\Time"][!Refresh]

[ButtonDescription33]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarCWIsoFormat#
X=235
Y=20r
[Button33a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#TIShowCWIsoFormat#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "TIShowCWIsoFormat" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"][!Refresh "#ROOTCONFIG#\Circles\Time"][!Refresh]
[Button33b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#TIShowCWIsoFormat#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "TIShowCWIsoFormat" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"][!Refresh "#ROOTCONFIG#\Circles\Time"][!Refresh]

; ----

[Divider3b]
Meter=Shape
Shape=Rectangle 232,150,156,2,0 | Fill Color 160,160,160

[Title3b]
Meter=String
MeterStyle=SettingsStyle-Text
X=235
Y=135
Text=#VarCalendar#


[ButtonDescription34]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarLeadingZeroes#
X=235
Y=25r
[Button34a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#LeadingZeroes#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "LeadingZeroes" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"][!Refresh "#ROOTCONFIG#\Circles\Time"][!Refresh]
[Button34b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#LeadingZeroes#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "LeadingZeroes" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"][!Refresh "#ROOTCONFIG#\Circles\Time"][!Refresh]

[ButtonDescription35]
Meter=String
MeterStyle=SettingsStyle-Text
Text=#VarStartOnMonday#
X=235
Y=20r
[Button35a]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#StartOnMonday#a.png
X=120r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "StartOnMonday" "1" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"][!Refresh "#ROOTCONFIG#\Circles\Time"][!Refresh]
[Button35b]
Meter=Button
ButtonImage=#@#Images\Buttons\Status#StartOnMonday#b.png
X=14r		
Y=0r
ButtonCommand=[!WriteKeyValue Variables "StartOnMonday" "0" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"][!Refresh "#ROOTCONFIG#\Circles\Time"][!Refresh]


;---- Time Format ----

[Background4]
Meter=Shape
Shape=Rectangle 10,140,210,70,3 | Fill Color 50,50,50

[Title4]
Meter=String
MeterStyle=SettingsStyle-Text
X=15
Y=145
Text=#VarTimeFormat#

[Divider4]
Meter=Shape
Shape=Rectangle 12,160,206,2,0 | Fill Color 160,160,160

[Button41]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn90x25.png
X=20
Y=170
ButtonCommand=[!WriteKeyValue Variables "Panel-TIFormat" 24H" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-TIFormat" 24H" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"][!Refresh "#ROOTCONFIG#\Circles\Time"]

[Button41Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=45r
Y=5r
Text=24H

[Button42]
Meter=Button
ButtonImage=#@#Images\Buttons\Btn90x25.png
X=55r
Y=-5r
ButtonCommand=[!WriteKeyValue Variables "Panel-TIFormat" 12H" "#@#Variables.inc"][!WriteKeyValue Variables "Circle-TIFormat" 12H" "#@#Variables.inc"][!Refresh "#ROOTCONFIG#\Panels\Time"][!Refresh "#ROOTCONFIG#\Circles\Time"]


[Button42Text]
Meter=String
MeterStyle=SettingsStyle-ButtonText
X=45r
Y=5r
Text=12H
