DROP TABLE SqlCounters;

CREATE TABLE SqlCounters(
hash varchar(32),
Year INT,
DayOfYear INT,
Extract INT8,
PRIMARY KEY(hash, Year,DayOfYear)
);
