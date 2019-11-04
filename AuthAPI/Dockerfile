FROM mcr.microsoft.com/dotnet/core/sdk:2.2-stretch AS build
ARG BUILDCONFIG=RELEASE
ARG VERSION=1.0.0

COPY AuthAPI.csproj /build/
RUN dotnet restore "./build/AuthAPI.csproj"
COPY . ./build/
WORKDIR /build/

#RUN dotnet build "AuthAPI.csproj" -c $BUILDCONFIG -o /app /p:version=$VERSION

#FROM build AS publish
RUN dotnet publish "AuthAPI.csproj" -c $BUILDCONFIG -o out /p:version=$VERSION

FROM mcr.microsoft.com/dotnet/core/aspnet:2.2-stretch-slim AS final
WORKDIR /app
COPY --from=build /build/out .
ENTRYPOINT ["dotnet", "AuthAPI.dll"]