
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
    }
  ]
};

/*************** DO NOT EDIT THE LINE BELOW ***************/
if (typeof module !== "undefined") { module.exports = config; }