-- drop table users;


create table users (
  id         serial primary key,
  uuid       varchar(64) not null unique,
  name       varchar(255),
  email      varchar(255) not null unique,
  password   varchar(255) not null,
  dateofbirth varchar(255) not null,
  created_at timestamp not null   
);

create table companies (
  id         serial primary key,
  name       varchar(255),
);