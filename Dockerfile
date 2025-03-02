FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 5002

ENV ASPNETCORE_URLS=http://+:5002

USER app
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG configuration=Release
ARG BUILD_VERSION
LABEL version=$BUILD_VERSION
WORKDIR /src
COPY ["src/Security/Security.csproj", "src/Security/"]
RUN dotnet restore "src/Security/Security.csproj"
COPY . .
WORKDIR "/src/src/Security"
RUN dotnet build "Security.csproj" -c $configuration -o /app/build

FROM build AS publish
ARG configuration=Release
RUN dotnet publish "Security.csproj" -c $configuration -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Security.dll"]
