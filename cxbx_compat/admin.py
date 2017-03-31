from django.contrib import admin
from django.db.models import Count, Max, Min

from .models import Build, Game, Title, Executable, XDKLibrary


class TitleInline(admin.StackedInline):
    model = Title
    extra = 0


class GameAdmin(admin.ModelAdmin):
    list_display = ('name', 'titles', 'exes')
    search_fields = ('name',)

    inlines = [TitleInline]

    def titles(self, obj):
        return obj.titles
    
    titles.admin_order_field = 'titles'
    
    def exes(self, obj):
        return obj.exes
    
    exes.admin_order_field = 'exes'
    
    def get_queryset(self, request):
        qs = super(GameAdmin, self).get_queryset(request)
        qs = qs.annotate(titles=Count('title', distinct=True), exes=Count('title__executable'))
        return qs


class ExecutableInline(admin.TabularInline):
    model = Executable.xdk_libraries.through
    extra = 0


class XDKLibraryAdmin(admin.ModelAdmin):
    list_display = ('name', 'xdk_version', 'qfe_version', 'exes')
    list_filter = ('name', 'xdk_version')

    fields = ['name', 'xdk_version', 'qfe_version']

    inlines = [ExecutableInline]

    search_fields = ('name', 'xdk_version')

    def exes(self, obj):
        return obj.exes

    exes.admin_order_field = 'exes'

    def get_queryset(self, request):
        qs = super(XDKLibraryAdmin, self).get_queryset(request)
        qs = qs.annotate(exes=Count('executable'))
        return qs


class ExecutableAdmin(admin.ModelAdmin):
    list_display = ('executable', 'title', 'min_xdk', 'max_xdk', 'libraries')
    search_fields = ('file_name', 'title__game__name', 'title__title_id')

    def executable(self, obj):
        return '{0}{1}'.format(obj.file_name, obj.disk_path)

    def get_queryset(self, request):
        qs = super(ExecutableAdmin, self).get_queryset(request)
        qs = qs.annotate(
            libraries=Count('xdk_libraries'),
            max_version=Max('xdk_libraries__xdk_version'),
            min_version=Min('xdk_libraries__xdk_version')
        )
        return qs

    def min_xdk(self, obj):
        return obj.min_version

    def max_xdk(self, obj):
        return obj.max_version

    def libraries(self, obj):
        return obj.libraries

    min_xdk.admin_order_field = 'min_version'
    max_xdk.admin_order_field = 'max_version'
    libraries.admin_order_field = 'libraries'


class TitleAdmin(admin.ModelAdmin):
    list_display = ('title_id', 'game', 'exes')
    search_fields = ('title_id', 'game__name')

    def exes(self, obj):
        return obj.exes

    def get_queryset(self, request):
        qs = super(TitleAdmin, self).get_queryset(request)
        qs = qs.annotate(exes=Count('executable'))
        return qs

    exes.admin_order_field = 'exes'

admin.site.register(Build)
admin.site.register(Game, GameAdmin)
admin.site.register(Title, TitleAdmin)
admin.site.register(Executable, ExecutableAdmin)
admin.site.register(XDKLibrary, XDKLibraryAdmin)

