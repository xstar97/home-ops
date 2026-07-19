
let config = {
  address: "0.0.0.0",
  port: 8080,
  ipWhitelist: [],

  modules: [
    {
      module: "alert",
    },
    {
      module: "updatenotification",
      position: "top_bar"
    },
    {
      module: "clock",
      position: "top_left"
    },
    {
      module: "calendar",
      position: "top_left",
      config: {
        calendars: [
          {
            symbol: "calendar-check",
            url: "https://google.com"
          }
        ]
      }
    },
    {
      module: "weather",
      position: "top_right",
      config: {
        weatherProvider: "openweathermap",
        weatherApiKey: "YOUR_API_KEY_HERE",
        lat: 39.2604,
        lon: -76.5165
      }
    },
    {
      module: "newsfeed",
      position: "bottom_bar",
      config: {
        feeds: [
          {
            title: "BBC News",
            url: "https://bbci.co.uk"
          }
        ],
        showSourceTitle: true,
        showPublishDate: true
      }
    }
  ]
};

/*************** DO NOT EDIT THE LINE BELOW ***************/
if (typeof module !== "undefined") { module.exports = config; }